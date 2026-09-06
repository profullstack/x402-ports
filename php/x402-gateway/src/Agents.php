<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

/** Which crawlers pay, and which read free. */
final class Agents
{
    /** Training-only crawlers: refused in robots.txt, charged by the gateway. */
    public const TRAINING = ['GPTBot', 'ClaudeBot', 'anthropic-ai', 'CCBot', 'meta-externalagent', 'FacebookBot', 'Bytespider', 'Applebot-Extended'];

    /** Retrieval crawlers, named in robots.txt so their operators can see they are welcome. */
    public const RETRIEVAL = ['OAI-SearchBot', 'ChatGPT-User', 'Claude-SearchBot', 'Claude-User', 'PerplexityBot', 'Perplexity-User', 'Google-Extended', 'Bingbot'];

    /** Whether a user agent names one of $agents (substring, case-insensitive). */
    public static function isTraining(?string $userAgent, array $agents = self::TRAINING): bool
    {
        $ua = strtolower((string) $userAgent);
        if ($ua === '') {
            return false;
        }
        foreach ($agents as $a) {
            if (str_contains($ua, strtolower($a))) {
                return true;
            }
        }
        return false;
    }
}
