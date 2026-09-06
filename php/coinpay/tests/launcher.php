<?php
declare(strict_types=1);
require __DIR__ . '/../src/Launcher.php';
use Profullstack\Coinpay\Launcher;
$fail = 0;
putenv('COINPAY_BIN=/opt/coinpay');
if (Launcher::command(['x402', 'pay', 'u']) !== ['/opt/coinpay', 'x402', 'pay', 'u']) { $fail++; fwrite(STDERR, "FAIL env bin\n"); }
putenv('COINPAY_BIN');
putenv('COINPAY_VERSION=0.8.0');
if (Launcher::spec() !== '@profullstack/coinpay@0.8.0') { $fail++; fwrite(STDERR, "FAIL spec\n"); }
putenv('COINPAY_VERSION');
$path = getenv('PATH');
putenv('PATH=/nonexistent');
if (Launcher::command([]) !== null) { $fail++; fwrite(STDERR, "FAIL nothing found\n"); }
putenv("PATH=$path");
echo $fail === 0 ? "3 checks, 0 failures\n" : "$fail failures\n";
exit($fail === 0 ? 0 : 1);
