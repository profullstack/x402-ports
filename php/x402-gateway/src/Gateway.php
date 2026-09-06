<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

/**
 * A gateway that sells crawl access to training crawlers, by the day, over x402.
 *
 * handle(Request) returns a Response to send, or null to let the request through.
 * Options carry the reference's names in snake_case; see the README.
 */
final class Gateway
{
    private const NO_STORE = ['cache-control' => 'no-store', 'vary' => 'Accept, User-Agent, X-Payment'];

    public readonly string $siteUrl;
    public readonly string $siteName;
    public readonly string $header;
    public readonly string $path;
    public readonly bool $enabled;
    public readonly string $buyUrl;
    private string $coinpayApiKey;
    private string $coinpayBaseUrl;
    private string $payTo;
    private float $priceCents;
    private string $currency;
    private int $passMinutes;
    private int $maxDays;
    private array $open;
    private array $denied;
    private bool $chargeSpoofed;
    /** @var ?callable */
    private $exempt;
    private array $training;
    private array $retrieval;
    /** @var callable */
    private $isPaidAgent;
    private string $secret;
    /** @var callable */
    private $page;
    private string $contact;
    /** @var ?callable */
    private $onSale;
    /** @var callable */
    private $post;
    /** @var callable */
    private $now;

    public function __construct(array $o)
    {
        $siteUrl = rtrim((string) ($o['site_url'] ?? ''), '/');
        if ($siteUrl === '') {
            throw new \InvalidArgumentException('Gateway needs site_url');
        }
        $this->siteUrl = $siteUrl;
        $host = parse_url($siteUrl, PHP_URL_HOST);
        $this->siteName = (string) ($o['site_name'] ?? (is_string($host) && $host !== '' ? $host : $siteUrl));
        $this->coinpayApiKey = (string) ($o['coinpay_api_key'] ?? '');
        $this->coinpayBaseUrl = rtrim((string) ($o['coinpay_base_url'] ?? 'https://coinpayportal.com'), '/');
        $this->payTo = (string) ($o['pay_to'] ?? '');
        $price = $o['price_cents'] ?? 100;
        $this->priceCents = is_numeric($price) && is_finite((float) $price) ? (float) $price : 100.0;
        $this->currency = (string) ($o['currency'] ?? 'USD');
        $pm = $o['pass_minutes'] ?? 1440;
        $this->passMinutes = is_int($pm) && $pm > 0 ? $pm : 1440;
        $md = $o['max_days'] ?? 30;
        $this->maxDays = is_int($md) && $md >= 1 ? $md : 30;
        $h = strtolower((string) ($o['header'] ?? 'x-crawl-pass'));
        $this->header = $h === '' ? 'x-crawl-pass' : $h;
        $p = (string) ($o['path'] ?? '/crawl');
        $this->path = $p === '' ? '/crawl' : $p;
        $this->open = array_merge(['/robots.txt', $this->path, '/security.txt', '/.well-known/'], array_values($o['open_paths'] ?? []));
        $this->denied = Edge::compileCidrs($o['deny_cidrs'] ?? []);
        $this->chargeSpoofed = (bool) ($o['charge_spoofed_browsers'] ?? false);
        $this->exempt = $o['exempt'] ?? null;
        $this->training = array_values($o['training'] ?? Agents::TRAINING);
        $this->retrieval = array_values($o['retrieval'] ?? Agents::RETRIEVAL);
        $training = $this->training;
        $this->isPaidAgent = $o['is_paid_agent'] ?? fn (string $ua): bool => Agents::isTraining($ua, $training);
        $this->secret = (string) ($o['secret'] ?? '') !== '' ? (string) $o['secret'] : $this->coinpayApiKey;
        $this->page = $o['page'] ?? [Page::class, 'render'];
        $this->contact = (string) ($o['contact'] ?? '');
        $this->onSale = $o['on_sale'] ?? null;
        $this->post = $o['post'] ?? [X402::class, 'post'];
        $this->now = $o['now'] ?? fn (): int => time();
        $this->enabled = $this->coinpayApiKey !== '' && $this->payTo !== '';
        $this->buyUrl = $this->siteUrl . $this->path;
    }

    public function money(float $cents): string
    {
        return number_format($cents / 100, 2, '.', '') . ' ' . $this->currency;
    }

    public function price(): string
    {
        return $this->money($this->priceCents);
    }

    private function isOpen(string $path): bool
    {
        foreach ($this->open as $p) {
            if (str_ends_with($p, '/') ? str_starts_with($path, $p) : $path === $p) {
                return true;
            }
        }
        return false;
    }

    private function daysFrom(Request $r): int
    {
        if (!preg_match('/^\s*([+-]?\d+)/', (string) $r->query('days'), $m)) {
            return 1;
        }
        $n = strlen($m[1]) > 18 ? ($m[1][0] === '-' ? 0 : PHP_INT_MAX) : (int) $m[1];
        return $n < 1 ? 1 : min($n, $this->maxDays);
    }

    /** The offer for $days terms: the same entries, $days times the price. */
    public function offer(int $days = 1): array
    {
        if (!$this->enabled) {
            return ['x402Version' => 2, 'accepts' => []];
        }
        $extra = $days > 1 ? " ($days × {$this->passMinutes})" : '';
        return X402::buildOffer($this->payTo, $this->priceCents * $days, $this->buyUrl, ($days * $this->passMinutes) . " minutes of crawl access to {$this->siteUrl}$extra");
    }

    public function receipt(int $days = 1, array $extra = []): array
    {
        $body = $this->offer($days);
        $body['pass'] = [
            'price' => $this->price(), 'minutes' => $this->passMinutes, 'days' => $days, 'total' => $this->money($this->priceCents * $days),
            'maxDays' => $this->maxDays, 'header' => $this->header,
            'buy' => $days > 1 ? "{$this->buyUrl}?days=$days" : $this->buyUrl, 'buyDays' => "{$this->buyUrl}?days=<n>",
        ];
        return array_merge($body, $extra);
    }

    public function pageCtx(int $days = 1): array
    {
        return [
            'days' => $days, 'total' => $this->money($this->priceCents * $days), 'site_name' => $this->siteName, 'site_url' => $this->siteUrl,
            'buy_url' => $this->buyUrl, 'price' => $this->price(), 'minutes' => $this->passMinutes, 'max_days' => $this->maxDays,
            'header' => $this->header, 'enabled' => $this->enabled, 'offer' => $this->offer(), 'training' => $this->training,
            'retrieval' => $this->retrieval, 'contact' => $this->contact,
        ];
    }

    /** robots.txt with this gateway's lists and sales path. Keys of $extra: disallow, allow, sitemap, refused, comments. */
    public function robotsTxt(array $extra = []): string
    {
        return Robots::txt(
            $extra['site_url'] ?? $this->siteUrl, $extra['disallow'] ?? [], $extra['allow'] ?? [],
            array_key_exists('sitemap', $extra) ? $extra['sitemap'] : null, $extra['path'] ?? $this->path, $extra['refused'] ?? [],
            $extra['training'] ?? $this->training, $extra['retrieval'] ?? $this->retrieval, $extra['comments'] ?? []
        );
    }

    /** The sales page as HTML, for a site that mounts it on a route of its own. */
    public function page(): string
    {
        return ($this->page)($this->pageCtx());
    }

    private function json(array $body, int $status, array $extra = []): Response
    {
        return new Response($status, array_merge(['content-type' => 'application/json; charset=utf-8'], self::NO_STORE, $extra),
            json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    private function html(string $body, int $status): Response
    {
        return new Response($status, array_merge(['content-type' => 'text/html; charset=utf-8'], self::NO_STORE), $body);
    }

    private function passFrom(Request $r): ?string
    {
        $direct = $r->header($this->header);
        if ($direct !== null && $direct !== '') {
            return trim($direct);
        }
        return preg_match('/^Bearer\s+(cp_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i', (string) $r->header('authorization'), $m) ? $m[1] : null;
    }

    /** Whether handling this request may call CoinPay (only a proof does). */
    public function needsIo(Request $r): bool
    {
        return $r->header('x-payment') !== null;
    }

    /** Answer one request with the sale: a pass as the body of a 200, or a 402 with the offer. */
    public function sell(Request $r): Response
    {
        $ua = (string) $r->header('user-agent');
        $proofHeader = $r->header('x-payment');
        $asked = $this->daysFrom($r);

        if ($proofHeader !== null && $proofHeader !== '') {
            if (!$this->enabled) {
                return $this->json($this->receipt($asked, ['error' => 'Payments are not switched on here.']), 402);
            }
            $payment = X402::decodePayment($proofHeader);
            if ($payment === null) {
                return $this->json($this->receipt($asked, ['error' => 'X-PAYMENT is not base64 JSON.']), 402);
            }
            $unit = X402::expectedFor($payment, $this->offer(1));
            if ($unit === null) {
                return $this->json($this->receipt($asked, ['error' => 'Proof does not match an offered network.']), 402);
            }
            $days = X402::daysPaid(X402::paidValueOf($payment), $unit['amount'], $this->maxDays);
            if ($days === 0) {
                return $this->json($this->receipt($asked, ['error' => "Pay a whole number of days: {$unit['amount']} per day in the token's smallest unit, up to {$this->maxDays} days. Add ?days=<n> to {$this->buyUrl} for the offer."]), 402);
            }
            $expected = X402::expectedFor($payment, $this->offer($days)) ?? $unit;
            $term = $days * $this->passMinutes * 60;
            $now = (int) ($this->now)();
            $result = X402::verifyAndSettle($payment, $expected, $this->coinpayApiKey, $this->coinpayBaseUrl, $this->post);

            $expiresAt = null;
            $replayed = false;
            if ($result['ok']) {
                $expiresAt = $now + $term;
            } elseif ($result['replay']) {
                $paid = X402::settleAgain($payment, $this->coinpayApiKey, $this->coinpayBaseUrl, $this->post);
                $validBefore = X402::validBeforeOf($payment);
                if ($paid && $validBefore !== null) {
                    $expiresAt = min($now + $term, $validBefore + $term);
                    $replayed = true;
                }
            }
            if ($expiresAt === null || $expiresAt <= $now) {
                return $this->json($this->receipt($days, ['error' => $result['reason'] ?? 'Payment could not be settled.']), 402);
            }

            $ref = X402::nonceOf($payment) ?? ($result['ref'] ?? null);
            $pass = Pass::mint($this->secret, $ref === null ? null : (string) $ref, $expiresAt, $now);
            $expires = gmdate('Y-m-d\TH:i:s', $pass['expires_at']) . '.000Z';
            if ($this->onSale !== null && !$replayed) {
                try {
                    ($this->onSale)([
                        'payer' => $result['payer'] ?? null, 'ref' => $ref, 'token' => $pass['token'], 'expires_at' => $expires, 'user_agent' => $ua,
                        'price_cents' => $this->priceCents, 'days' => $days, 'total_cents' => $this->priceCents * $days, 'currency' => $this->currency,
                    ]);
                } catch (\Throwable) {
                    // accounting must never cost a buyer the pass
                }
            }
            return $this->json([
                'ok' => true, 'pass' => $pass['token'], 'expires_at' => $expires, 'days' => $days, 'minutes' => $days * $this->passMinutes,
                'header' => $this->header, 'replayed' => $replayed, 'use' => "curl -H \"{$this->header}: {$pass['token']}\" {$this->siteUrl}/",
            ], 200, [$this->header => $pass['token'], "{$this->header}-expires" => $expires]);
        }

        if (str_contains(strtolower((string) $r->header('accept')), 'text/html')) {
            return $this->html(($this->page)($this->pageCtx($asked)), 402);
        }
        return $this->json($this->receipt($asked, ['error' => "Payment required for training crawlers. Read {$this->buyUrl} for how."]), 402);
    }

    /** The gate. Null means "not for me, carry on". */
    public function handle(Request $r): ?Response
    {
        if ($this->denied !== [] && Edge::inCidrs(Edge::clientIp($r), $this->denied)) {
            return new Response(403, array_merge(['content-type' => 'text/plain; charset=utf-8'], self::NO_STORE), "Not available from this network.\n");
        }
        $path = $r->path();
        if ($path === $this->path) {
            return $this->sell($r);
        }
        if ($this->exempt !== null && ($this->exempt)($r)) {
            return null;
        }
        $pays = ($this->isPaidAgent)((string) $r->header('user-agent')) || ($this->chargeSpoofed && Edge::isSpoofedBrowser($r));
        if (!$pays || $this->isOpen($path)) {
            return null;
        }
        $token = $this->passFrom($r);
        if ($token !== null && Pass::read($token, $this->secret, (int) ($this->now)()) !== null) {
            return null;
        }
        return $this->sell($r);
    }

    /**
     * Plain PHP: read the globals, and if the gateway answers, send it and return true.
     * Put `if ($gateway->handleGlobals()) exit;` at the top of your front controller.
     */
    public function handleGlobals(?array $server = null): bool
    {
        $answer = $this->handle(Request::fromGlobals($server));
        if ($answer === null) {
            return false;
        }
        $answer->send();
        return true;
    }
}
