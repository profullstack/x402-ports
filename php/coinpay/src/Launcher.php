<?php
declare(strict_types=1);

namespace Profullstack\Coinpay;

/**
 * A launcher for the CoinPay CLI, @profullstack/coinpay on npm.
 * Order: $COINPAY_BIN; a coinpay on PATH that is not this launcher; then npx, bunx, pnpm dlx or deno run.
 * $COINPAY_VERSION pins the npm version.
 */
final class Launcher
{
    public const PACKAGE = '@profullstack/coinpay';

    public static function spec(): string
    {
        $v = (string) getenv('COINPAY_VERSION');
        return $v === '' ? self::PACKAGE : self::PACKAGE . "@$v";
    }

    public static function which(string $name): ?string
    {
        $exts = PHP_OS_FAMILY === 'Windows' ? ['.exe', '.cmd', '.bat', ''] : [''];
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            foreach ($exts as $ext) {
                $p = $dir . DIRECTORY_SEPARATOR . $name . $ext;
                if (is_file($p) && is_executable($p)) {
                    return $p;
                }
            }
        }
        return null;
    }

    private static function realCli(string $me): ?string
    {
        $found = self::which('coinpay');
        if ($found === null) {
            return null;
        }
        $a = realpath($found);
        $b = realpath($me);
        return $a !== false && $b !== false && $a === $b ? null : $found;
    }

    /** @return ?string[] */
    public static function command(array $args, string $me = ''): ?array
    {
        $exe = (string) getenv('COINPAY_BIN');
        if ($exe !== '') {
            return [$exe, ...$args];
        }
        $real = self::realCli($me);
        if ($real !== null) {
            return [$real, ...$args];
        }
        $runners = [['npx', '--yes', self::spec()], ['bunx', self::spec()], ['pnpm', 'dlx', self::spec()], ['deno', 'run', '-A', 'npm:' . self::spec()]];
        foreach ($runners as $r) {
            if (self::which($r[0]) !== null) {
                return [...$r, ...$args];
            }
        }
        return null;
    }

    public static function main(array $args, string $me): int
    {
        $cmd = self::command($args, $me);
        if ($cmd === null) {
            fwrite(STDERR, "coinpay: the CoinPay CLI runs on Node.js 20+ (or Bun or Deno), and none was found.\n  Install Node from https://nodejs.org, then either run this command again\n  or install the CLI directly: npm install -g @profullstack/coinpay\n");
            return 127;
        }
        $p = proc_open($cmd, [0 => STDIN, 1 => STDOUT, 2 => STDERR], $pipes);
        if (!is_resource($p)) {
            fwrite(STDERR, "coinpay: could not run {$cmd[0]}\n");
            return 126;
        }
        return proc_close($p);
    }
}
