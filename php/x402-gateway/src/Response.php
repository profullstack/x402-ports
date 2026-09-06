<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

final class Response
{
    /** @param array<string, string> $headers */
    public function __construct(public readonly int $status, public readonly array $headers, public readonly string $body)
    {
    }

    /** Send it with PHP's own header()/echo. */
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) {
            header("$k: $v");
        }
        header('content-length: ' . strlen($this->body));
        echo $this->body;
    }
}
