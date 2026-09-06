<?php
declare(strict_types=1);

namespace Profullstack\X402Gateway;

final class Robots
{
    /**
     * robots.txt with the crawlers sorted the way the gateway sorts them.
     * $sitemap: null for <siteUrl>/sitemap.xml, '' to omit.
     */
    public static function txt(string $siteUrl, array $disallow = [], array $allow = [], ?string $sitemap = null, string $path = '/crawl', array $refused = [], array $training = Agents::TRAINING, array $retrieval = Agents::RETRIEVAL, array $comments = []): string
    {
        if ($siteUrl === '') {
            throw new \InvalidArgumentException('robots needs siteUrl');
        }
        $base = rtrim($siteUrl, '/');
        $map = $sitemap ?? "$base/sitemap.xml";
        $welcome = function (string $agent) use ($allow, $disallow): string {
            $lines = ["User-agent: $agent", 'Allow: /'];
            foreach ($allow as $p) {
                $lines[] = "Allow: $p";
            }
            foreach ($disallow as $p) {
                $lines[] = "Disallow: $p";
            }
            return implode("\n", $lines);
        };
        $refuse = fn (string $agent): string => "User-agent: $agent\nDisallow: /";
        $charge = fn (string $agent): string => $refuse($agent) . "\nAllow: $path";
        $lines = array_map(fn ($c) => "# $c", $comments);
        if ($comments !== []) {
            $lines[] = '';
        }
        foreach ($refused as $a) {
            $lines[] = $refuse($a) . "\n";
        }
        foreach ($training as $a) {
            $lines[] = $charge($a) . "\n";
        }
        foreach ($retrieval as $a) {
            $lines[] = $welcome($a) . "\n";
        }
        $lines[] = $welcome('*');
        $lines[] = '';
        if ($map !== '') {
            $lines[] = "Sitemap: $map";
            $lines[] = '';
        }
        return implode("\n", $lines);
    }
}
