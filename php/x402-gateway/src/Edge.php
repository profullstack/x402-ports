<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

/** The two checks that do not need a user agent to be honest: where it came from, and whether it is the browser it claims. */
final class Edge
{
    private static function ipv4ToInt(string $ip): ?int
    {
        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            return null;
        }
        $n = 0;
        foreach ($parts as $p) {
            if (!preg_match('/^\d{1,3}$/', $p)) {
                return null;
            }
            $v = (int) $p;
            if ($v > 255) {
                return null;
            }
            $n = $n * 256 + $v;
        }
        return $n;
    }

    /** "a.b.c.d/len" or a bare address -> ['base', 'mask', 'text']. Null if unreadable. */
    public static function parseCidr(string $cidr): ?array
    {
        $s = trim($cidr);
        $slash = strpos($s, '/');
        $ip = $slash === false ? $s : substr($s, 0, $slash);
        $base = self::ipv4ToInt($ip);
        if ($base === null) {
            return null;
        }
        if ($slash === false) {
            $len = 32;
        } else {
            $lenRaw = substr($s, $slash + 1);
            if (!preg_match('/^\d+$/', $lenRaw) || (int) $lenRaw > 32) {
                return null;
            }
            $len = (int) $lenRaw;
        }
        $mask = $len === 0 ? 0 : (0xffffffff << (32 - $len)) & 0xffffffff;
        return ['base' => $base & $mask, 'mask' => $mask, 'text' => "$ip/$len"];
    }

    public static function compileCidrs(array $list): array
    {
        $out = [];
        foreach ($list as $c) {
            $p = self::parseCidr((string) $c);
            if ($p !== null) {
                $out[] = $p;
            }
        }
        return $out;
    }

    public static function inCidrs(?string $ip, array $compiled): bool
    {
        $n = self::ipv4ToInt(trim((string) $ip));
        if ($n === null) {
            return false;
        }
        foreach ($compiled as $c) {
            if (($n & $c['mask']) === $c['base']) {
                return true;
            }
        }
        return false;
    }

    /** The caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop. */
    public static function clientIp(Request $r): string
    {
        $real = trim((string) $r->header('x-real-ip'));
        if ($real !== '') {
            return $real;
        }
        $xff = $r->header('x-forwarded-for');
        if ($xff === null) {
            return '';
        }
        $hops = array_values(array_filter(array_map('trim', explode(',', $xff)), fn ($h) => $h !== ''));
        return $hops === [] ? '' : end($hops);
    }

    /** Claims Chromium, declares no crawler, sends no Sec-Fetch-Mode: an HTTP client with a copied string. */
    public static function isSpoofedBrowser(Request $r): bool
    {
        $ua = (string) $r->header('user-agent');
        if (!preg_match('#\bChrome/\d+#', $ua)) {
            return false;
        }
        if (preg_match('#compatible;|\bbot\b|bot/|crawler|spider|slurp#i', $ua)) {
            return false;
        }
        return $r->header('sec-fetch-mode') === null;
    }
}
