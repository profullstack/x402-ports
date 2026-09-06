<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

/** Passes: signed, self-describing tokens, cp_<payload>.<hmac-sha256>. No table behind them. */
final class Pass
{
    public static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function sign(string $secret, string $data): string
    {
        return self::b64url(hash_hmac('sha256', $data, $secret, true));
    }

    /** @return array{token: string, expires_at: int, ref: ?string} */
    public static function mint(string $secret, ?string $ref, int $expiresAt, ?int $now = null): array
    {
        $now ??= time();
        if ($secret === '') {
            throw new \InvalidArgumentException('a pass needs a signing secret');
        }
        if ($expiresAt <= $now) {
            throw new \InvalidArgumentException('a pass needs a future expiry');
        }
        $payload = self::b64url(json_encode(['v' => 1, 'iat' => $now, 'exp' => $expiresAt, 'ref' => $ref], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return ['token' => "cp_$payload." . self::sign($secret, $payload), 'expires_at' => $expiresAt, 'ref' => $ref];
    }

    /** The claims when the signature holds and the pass is live, else null. Never throws on garbage. */
    public static function read(mixed $token, string $secret, ?int $now = null): ?array
    {
        $now ??= time();
        if ($secret === '' || !is_string($token) || !str_starts_with($token, 'cp_')) {
            return null;
        }
        $dot = strpos($token, '.');
        if ($dot === false) {
            return null;
        }
        $payload = substr($token, 3, $dot - 3);
        $sig = substr($token, $dot + 1);
        if ($payload === '' || $sig === '') {
            return null;
        }
        if (!hash_equals(self::sign($secret, $payload), $sig)) {
            return null;
        }
        $raw = base64_decode(strtr($payload, '-_', '+/') . str_repeat('=', (4 - strlen($payload) % 4) % 4), true);
        if ($raw === false) {
            return null;
        }
        $claims = json_decode($raw, true);
        if (!is_array($claims) || ($claims['v'] ?? null) !== 1) {
            return null;
        }
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) && !is_float($exp)) {
            return null;
        }
        if (is_float($exp) && !is_finite($exp)) {
            return null;
        }
        if ($exp <= $now) {
            return null;
        }
        return ['exp' => $exp, 'iat' => $claims['iat'] ?? null, 'ref' => $claims['ref'] ?? null];
    }
}
