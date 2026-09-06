<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

/** x402 v2 in CoinPay's dialect: the offer, the proof, and the verify/settle calls. */
final class X402
{
    /** USDC on Base, Polygon and Ethereum, Base first. */
    public const METHODS = [
        ['key' => 'usdc_base', 'network' => 'eip155:8453', 'asset' => '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'label' => 'USDC on Base'],
        ['key' => 'usdc_polygon', 'network' => 'eip155:137', 'asset' => '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', 'label' => 'USDC on Polygon'],
        ['key' => 'usdc_eth', 'network' => 'eip155:1', 'asset' => '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'label' => 'USDC on Ethereum'],
    ];

    /** A v2 402 body. amount is the price in the token's smallest unit, rounded up. */
    public static function buildOffer(string $payTo, float $priceCents, string $resource, string $description = 'Payment required', int $maxTimeoutSeconds = 300, array $methods = self::METHODS): array
    {
        if ($payTo === '') {
            throw new \InvalidArgumentException('an offer needs a payTo address');
        }
        $amount = (string) (int) ceil(($priceCents / 100) * 1000000);
        $accepts = [];
        foreach ($methods as $m) {
            $accepts[] = [
                'scheme' => 'exact', 'network' => $m['network'], 'amount' => $amount, 'asset' => $m['asset'], 'payTo' => $payTo,
                'resource' => $resource, 'description' => $description, 'mimeType' => 'application/json',
                'maxTimeoutSeconds' => $maxTimeoutSeconds, 'extra' => ['name' => 'USD Coin', 'version' => '2'],
            ];
        }
        return ['x402Version' => 2, 'accepts' => $accepts];
    }

    /** base64 or base64url to text, the forgiving way atob reads it. Null if it is not base64. */
    public static function fromBase64(string $s): ?string
    {
        $t = strtr(preg_replace('/\s+/', '', $s) ?? '', '-_', '+/');
        if (strlen($t) % 4 === 0) {
            $t = rtrim($t, '=');
        }
        if (strlen($t) % 4 === 1 || !preg_match('#^[A-Za-z0-9+/]*={0,2}$#', $t)) {
            return null;
        }
        $t = rtrim($t, '=');
        $out = base64_decode($t . str_repeat('=', (4 - strlen($t) % 4) % 4), true);
        return $out === false ? null : $out;
    }

    /** The proof out of an X-PAYMENT header: an array (object or list), else null. */
    public static function decodePayment(?string $header): ?array
    {
        if ($header === null || $header === '') {
            return null;
        }
        $text = self::fromBase64($header);
        if ($text === null) {
            return null;
        }
        $parsed = json_decode($text, true);
        return is_array($parsed) ? $parsed : null;
    }

    public static function dig(mixed $obj, string ...$path): mixed
    {
        foreach ($path as $k) {
            if (!is_array($obj) || !array_key_exists($k, $obj)) {
                return null;
            }
            $obj = $obj[$k];
        }
        return $obj;
    }

    private static function str(mixed $v): string
    {
        if ($v === null || is_array($v)) {
            return '';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        return (string) $v;
    }

    /** What CoinPay must hold the proof to, from the OFFERED entry for its network. */
    public static function expectedFor(mixed $payment, array $offer): ?array
    {
        $network = strtolower(self::str(is_array($payment) ? ($payment['network'] ?? null) : null));
        foreach ($offer['accepts'] ?? [] as $a) {
            if (strtolower($a['network']) === $network) {
                return ['amount' => $a['amount'], 'resource' => $a['resource'], 'payTo' => $a['payTo'], 'asset' => $a['asset']];
            }
        }
        return null;
    }

    public static function nonceOf(mixed $payment): ?string
    {
        $v = self::dig($payment, 'payload', 'authorization', 'nonce');
        return $v === null ? null : self::str($v);
    }

    public static function validBeforeOf(mixed $payment): ?int
    {
        $raw = trim(self::str(self::dig($payment, 'payload', 'authorization', 'validBefore')));
        if ($raw === '' || !is_numeric($raw)) {
            return null;
        }
        $f = (float) $raw;
        return is_finite($f) && $f > 0 ? (int) $f : null;
    }

    /**
     * What BigInt(raw) would read, as a decimal string without sign: decimal or 0x strings, whole
     * numbers. Null when unreadable. Values beyond 64 bits need ext-bcmath or ext-gmp; without
     * either they are refused (null), never mis-read.
     */
    public static function bigint(mixed $raw): ?string
    {
        if (is_bool($raw) || $raw === null || is_array($raw)) {
            return null;
        }
        if (is_int($raw)) {
            return (string) $raw;
        }
        if (is_float($raw)) {
            return is_finite($raw) && floor($raw) === $raw ? number_format($raw, 0, '', '') : null;
        }
        $s = trim((string) $raw);
        if (preg_match('/^[+-]?\d+$/', $s)) {
            $s = ltrim($s, '+');
            if (strlen(ltrim($s, '-')) > 18 && !function_exists('bcadd') && !function_exists('gmp_init')) {
                return null;
            }
            return $s;
        }
        if (preg_match('/^0[xX][0-9a-fA-F]+$/', $s)) {
            $h = substr($s, 2);
            if (strlen($h) <= 15) {
                return (string) hexdec($h);
            }
            if (function_exists('gmp_init')) {
                return gmp_strval(gmp_init($h, 16), 10);
            }
            return null;
        }
        return null;
    }

    private static function cmp(string $a, string $b): int
    {
        if (function_exists('bccomp')) {
            return bccomp($a, $b, 0);
        }
        if (function_exists('gmp_cmp')) {
            return gmp_cmp($a, $b);
        }
        return (int) $a <=> (int) $b;
    }

    /** [quotient, remainder] of two non-negative decimal strings. */
    private static function divmod(string $a, string $b): array
    {
        if (function_exists('bcdiv')) {
            return [bcdiv($a, $b, 0), bcmod($a, $b, 0)];
        }
        if (function_exists('gmp_div_qr')) {
            [$q, $r] = gmp_div_qr($a, $b);
            return [gmp_strval($q), gmp_strval($r)];
        }
        return [(string) intdiv((int) $a, (int) $b), (string) ((int) $a % (int) $b)];
    }

    /** The value a proof authorizes, in the token's smallest unit, or null. */
    public static function paidValueOf(mixed $payment): ?string
    {
        $raw = self::dig($payment, 'payload', 'authorization', 'value');
        if ($raw === null || $raw === '') {
            return null;
        }
        $v = self::bigint($raw);
        return $v !== null && $v[0] !== '-' && self::cmp($v, '0') > 0 ? $v : null;
    }

    /** How many terms $value buys at $unit per term: a whole number in [1, maxDays], else 0. */
    public static function daysPaid(?string $value, string $unit, int $maxDays): int
    {
        if ($value === null) {
            return 0;
        }
        $per = self::bigint($unit);
        if ($per === null || $per[0] === '-' || self::cmp($per, '0') <= 0) {
            return 0;
        }
        [$q, $r] = self::divmod($value, $per);
        if ($r !== '0' || self::cmp($q, '1') < 0 || self::cmp($q, (string) $maxDays) > 0) {
            return 0;
        }
        return (int) $q;
    }

    /** POST JSON. Returns [status, body]. A transport error is [0, '']. */
    public static function post(string $url, array $headers, string $body): array
    {
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = "$k: $v";
        }
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $lines, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 20]);
            $text = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
            return $text === false ? [0, ''] : [$status, (string) $text];
        }
        $ctx = stream_context_create(['http' => ['method' => 'POST', 'header' => implode("\r\n", $lines), 'content' => $body, 'timeout' => 20, 'ignore_errors' => true]]);
        $text = @file_get_contents($url, false, $ctx);
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $h, $m)) {
                $status = (int) $m[1];
            }
        }
        return $text === false ? [0, ''] : [$status, $text];
    }

    private static function obj(string $text): array
    {
        $v = json_decode($text, true);
        return is_array($v) ? $v : [];
    }

    private static function truthy(mixed $v): bool
    {
        return !($v === null || $v === false || $v === '' || $v === 0 || $v === 0.0);
    }

    /** Verify, then settle. ['ok' => true, 'payer', 'ref'] or ['ok' => false, 'reason', 'replay']. */
    public static function verifyAndSettle(mixed $payment, array $expected, string $apiKey, string $baseUrl, callable $post): array
    {
        $call = function (string $path, array $body) use ($apiKey, $baseUrl, $post): array {
            [$status, $text] = $post($baseUrl . $path, ['content-type' => 'application/json', 'x-api-key' => $apiKey], json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
            return [$status, self::obj($text)];
        };
        [$vs, $v] = $call('/api/x402/verify', ['payment' => $payment, 'expected' => $expected]);
        if (!self::truthy($v['valid'] ?? null)) {
            $reason = self::str($v['error'] ?? $v['reason'] ?? "verify failed ($vs)");
            return ['ok' => false, 'reason' => $reason, 'replay' => (bool) preg_match('/already used|replay/i', $reason)];
        }
        [$ss, $s] = $call('/api/x402/settle', ['payment' => $payment]);
        if (!self::truthy($s['settled'] ?? null)) {
            $reason = self::str($s['error'] ?? "settle failed ($ss)");
            return ['ok' => false, 'reason' => $reason, 'replay' => (bool) preg_match('/already settled|already being settled/i', $reason)];
        }
        $ref = $s['txHash'] ?? null;
        if ($ref === null || $ref === '') {
            $ref = self::nonceOf($payment);
        }
        return ['ok' => true, 'payer' => self::dig($v, 'payment', 'from'), 'ref' => $ref];
    }

    /** Whether the proof has already been paid, when a settle is asked about twice. */
    public static function settleAgain(mixed $payment, string $apiKey, string $baseUrl, callable $post): bool
    {
        [, $text] = $post("$baseUrl/api/x402/settle", ['content-type' => 'application/json', 'x-api-key' => $apiKey], json_encode(['payment' => $payment], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $s = self::obj($text);
        return self::truthy($s['settled'] ?? null) || (bool) preg_match('/already settled/i', self::str($s['error'] ?? ''));
    }
}
