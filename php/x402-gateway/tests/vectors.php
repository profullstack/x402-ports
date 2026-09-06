<?php
declare(strict_types=1);

// Every port runs the same fixtures: spec/vectors.json, generated from the JS reference.
spl_autoload_register(function (string $c): void {
    $p = __DIR__ . '/../src/' . str_replace('Profullstack\\X402Gateway\\', '', $c) . '.php';
    if (str_starts_with($c, 'Profullstack\\X402Gateway\\') && is_file($p)) {
        require $p;
    }
});

use Profullstack\X402Gateway\{Agents, Edge, Gateway, Pass, Request, Robots, X402};

$V = json_decode(file_get_contents(getenv('X402_VECTORS') ?: __DIR__ . '/../../../spec/vectors.json'), true);
$C = $V['constants'];
$NOW = $C['NOW'];
$SITE = $C['SITE'];
$failures = 0;
$checks = 0;
function eq(mixed $want, mixed $got, string $name): void
{
    global $failures, $checks;
    $checks++;
    if ($want !== $got) {
        $failures++;
        fwrite(STDERR, "FAIL $name\n  want " . json_encode($want, JSON_UNESCAPED_SLASHES) . "\n  got  " . json_encode($got, JSON_UNESCAPED_SLASHES) . "\n");
    }
}

function gateway(array $V, ?callable $post = null, array $extra = []): Gateway
{
    $g = $V['gateway'];
    $sub = $g['exempt'];
    return new Gateway(array_merge([
        'site_url' => $g['siteUrl'], 'coinpay_api_key' => $g['coinpay']['apiKey'], 'pay_to' => $g['payTo'],
        'deny_cidrs' => $g['denyCidrs'], 'charge_spoofed_browsers' => $g['chargeSpoofedBrowsers'], 'open_paths' => $g['openPaths'],
        'exempt' => fn (Request $r) => str_contains((string) $r->header('cookie'), $sub),
        'now' => fn () => $V['constants']['NOW'],
        'post' => $post ?? function (string $url) { throw new RuntimeException("CoinPay must not be called: $url"); },
    ], $extra));
}

// passes
foreach ($V['passes'] as $p) {
    eq($p['token'], Pass::mint($p['secret'], $p['ref'], $p['exp'], $p['iat'])['token'], 'mint ' . json_encode($p['ref']));
}
foreach ($V['readPass'] as $c) {
    $r = Pass::read($c['token'], $c['secret'] ?? $C['SECRET'], $c['now']);
    eq($c['ok'], $r !== null, 'read ' . ($c['why'] ?? $c['token']));
    if ($c['ok']) {
        eq($c['claims'], $r, 'claims');
    }
}
// offers, payments, days
foreach ($V['offers'] as $o) {
    $i = $o['in'];
    eq($o['out'], X402::buildOffer($i['payTo'], (float) $i['priceCents'], $i['resource'], $i['description'], $i['maxTimeoutSeconds'] ?? 300), 'offer ' . $i['priceCents']);
}
$offer = $V['offers'][0]['out'];
foreach ($V['payments'] as $p) {
    $d = X402::decodePayment($p['header']);
    eq($p['decodes'], $d !== null, 'decode ' . ($p['why'] ?? substr($p['header'], 0, 20)));
    if (array_key_exists('expected', $p)) {
        eq($p['expected'], X402::expectedFor($d, $offer), 'expectedFor ' . ($p['why'] ?? ''));
    }
}
foreach ($V['daysPaid'] as $d) {
    $v = $d['value'] === null ? null : X402::bigint($d['value']);
    if ($v !== null && ($v[0] === '-' || $v === '0')) {
        $v = null;
    }
    eq($d['days'], X402::daysPaid($v, $d['unit'], $d['maxDays']), 'daysPaid ' . json_encode($d['value']) . ' ' . ($d['why'] ?? ''));
}
// agents, edge, robots
foreach ($V['agents'] as $a) {
    eq($a['training'], Agents::isTraining($a['ua']), 'agent ' . $a['ua']);
}
$c = Edge::compileCidrs($V['cidrs']['list']);
eq($V['cidrs']['compiled'], array_map(fn ($x) => $x['text'], $c), 'compiled cidrs');
foreach ($V['cidrs']['cases'] as $k) {
    eq($k['hit'], Edge::inCidrs($k['ip'], $c), 'cidr ' . $k['ip']);
}
$n = Edge::compileCidrs($V['cidrs']['narrow']['list']);
foreach ($V['cidrs']['narrow']['cases'] as $k) {
    eq($k['hit'], Edge::inCidrs($k['ip'], $n), 'narrow cidr ' . $k['ip']);
}
foreach ($V['clientIp'] as $k) {
    eq($k['ip'], Edge::clientIp(new Request("$SITE/", $k['headers'])), 'clientIp ' . json_encode($k['headers']));
}
foreach ($V['spoofs'] as $s) {
    eq($s['spoofed'], Edge::isSpoofedBrowser(new Request("$SITE/", array_merge(['user-agent' => $s['ua']], $s['headers']))), 'spoof ' . $s['ua']);
}
foreach ($V['robots'] as $idx => $r) {
    $i = $r['in'];
    eq($r['out'], Robots::txt($i['siteUrl'], $i['disallow'] ?? [], $i['allow'] ?? [], array_key_exists('sitemap', $i) ? $i['sitemap'] : null, $i['path'] ?? '/crawl', $i['refused'] ?? [], $i['training'] ?? Agents::TRAINING, $i['retrieval'] ?? Agents::RETRIEVAL, $i['comments'] ?? []), "robots $idx");
}
// handle
$check = function (Gateway $gw, array $c) use ($SITE): void {
    $r = $gw->handle(new Request($SITE . $c['url'], array_change_key_case($c['headers'], CASE_LOWER)));
    if ($c['pass'] ?? false) {
        eq(null, $r, $c['name']);
        return;
    }
    if ($r === null) {
        eq($c['status'], null, $c['name'] . ' (passed through)');
        return;
    }
    eq($c['status'], $r->status, $c['name'] . ' status');
    if (isset($c['contentType'])) {
        eq($c['contentType'], explode(';', $r->headers['content-type'])[0], $c['name'] . ' content-type');
    }
    if (array_key_exists('body', $c)) {
        eq($c['body'], json_decode($r->body, true), $c['name'] . ' body');
    }
    if (isset($c['text'])) {
        eq($c['text'], $r->body, $c['name'] . ' text');
    }
    foreach ($c['htmlContains'] ?? [] as $s) {
        eq(true, str_contains($r->body, $s), $c['name'] . " html contains $s");
    }
    foreach ($c['responseHeaders'] ?? [] as $k => $v) {
        eq($v, $r->headers[$k] ?? null, $c['name'] . " header $k");
    }
};
$gw = gateway($V);
foreach ($V['handle'] as $c) {
    $check($gw, $c);
}
$d = new Gateway(['site_url' => $SITE, 'now' => fn () => $NOW]);
foreach ($V['disabled'] as $c) {
    $check($d, $c);
}
eq(Robots::txt($SITE), $gw->robotsTxt(), 'gateway robots');
eq(true, str_contains($gw->page(), '1.00 USD'), 'page has price');
// globals
$server = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/some?x=1', 'HTTPS' => 'on', 'HTTP_HOST' => 'example.com', 'HTTP_USER_AGENT' => 'GPTBot'];
$req = Request::fromGlobals($server);
eq('https://example.com/some?x=1', $req->url, 'fromGlobals url');
eq(402, $gw->handle($req)?->status, 'fromGlobals gptbot 402');
// paid
foreach ($V['coinpay']['paid'] as $c) {
    $calls = [];
    $post = function (string $url, array $headers, string $body) use (&$calls, $c, $C): array {
        eq($C['SECRET'], $headers['x-api-key'], 'api key');
        $calls[] = [$url, json_decode($body, true)];
        $settles = count(array_filter($calls, fn ($x) => str_ends_with($x[0], '/api/x402/settle')));
        if (str_ends_with($url, '/api/x402/verify')) {
            $out = $c['verify'];
        } elseif ($settles === 1 && isset($c['settle'])) {
            $out = $c['settle'];
        } else {
            $out = $c['settleAgain'] ?? $c['settle'] ?? [];
        }
        return [200, json_encode($out)];
    };
    $sales = [];
    $g = gateway($V, $post, ['on_sale' => function (array $s) use (&$sales) { $sales[] = $s; }]);
    $r = $g->handle(new Request("$SITE/crawl", ['x-payment' => base64_encode(json_encode($c['proof'])), 'user-agent' => 'curl/8']));
    eq($c['status'], $r->status, $c['name'] . ' status');
    $body = json_decode($r->body, true);
    if ($c['status'] === 200) {
        eq(true, $body['ok'], $c['name']);
        eq($c['days'], $body['days'], $c['name'] . ' days');
        if (isset($c['minutes'])) {
            eq($c['minutes'], $body['minutes'], $c['name'] . ' minutes');
        }
        eq($c['replayed'], $body['replayed'], $c['name'] . ' replayed');
        $claims = Pass::read($body['pass'], $C['SECRET'], $NOW);
        eq(true, $claims !== null, $c['name'] . ' pass reads back');
        if (isset($c['ref'])) {
            eq($c['ref'], $claims['ref'], $c['name'] . ' ref');
        }
        if (isset($c['expiresAt'])) {
            eq($c['expiresAt'], $claims['exp'], $c['name'] . ' exp');
        }
        eq($body['pass'], $r->headers['x-crawl-pass'], $c['name'] . ' pass header');
        eq($c['replayed'] ? 0 : 1, count($sales), $c['name'] . ' sales');
        eq((string) (1000000 * $c['days']), $calls[0][1]['expected']['amount'], $c['name'] . ' verify amount');
    } else {
        if (isset($c['error'])) {
            eq($c['error'], $body['error'], $c['name'] . ' error');
        }
        eq(0, count($sales), $c['name'] . ' no sale');
    }
}
echo "$checks checks, $failures failures\n";
exit($failures === 0 ? 0 : 1);
