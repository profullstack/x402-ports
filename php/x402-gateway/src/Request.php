<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

/** The little the gateway needs to know about a request. Header names are lower-cased. */
final class Request
{
    /** @param array<string, string> $headers lower-cased names; multi-valued headers joined with ", " */
    public function __construct(public readonly string $url, public readonly array $headers = [], public readonly string $method = 'GET')
    {
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function path(): string
    {
        $p = parse_url($this->url, PHP_URL_PATH);
        return is_string($p) && $p !== '' ? $p : '/';
    }

    public function query(string $name): ?string
    {
        $q = parse_url($this->url, PHP_URL_QUERY);
        if (!is_string($q)) {
            return null;
        }
        foreach (explode('&', $q) as $kv) {
            [$k, $v] = array_pad(explode('=', $kv, 2), 2, '');
            if (urldecode($k) === $name) {
                return urldecode($v);
            }
        }
        return null;
    }

    /** From PHP's globals ($_SERVER), for a plain script or front controller. */
    public static function fromGlobals(?array $server = null): self
    {
        $server ??= $_SERVER;
        $headers = [];
        foreach ($server as $k => $v) {
            if (str_starts_with($k, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = (string) $v;
            }
        }
        if (isset($server['CONTENT_TYPE'])) {
            $headers['content-type'] ??= (string) $server['CONTENT_TYPE'];
        }
        $https = ($server['HTTPS'] ?? '') !== '' && ($server['HTTPS'] ?? '') !== 'off';
        $scheme = $https ? 'https' : 'http';
        $host = $headers['host'] ?? ($server['SERVER_NAME'] ?? 'localhost');
        $uri = (string) ($server['REQUEST_URI'] ?? '/');
        return new self("$scheme://$host$uri", $headers, (string) ($server['REQUEST_METHOD'] ?? 'GET'));
    }
}
