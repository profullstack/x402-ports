"""``coinpay`` from pip: a launcher for the CoinPay CLI, @profullstack/coinpay on npm.

The CLI is JavaScript. This package finds a way to run it and hands over the
arguments, in this order:

1. ``$COINPAY_BIN`` if set.
2. A ``coinpay`` on PATH that is not this launcher (``npm i -g @profullstack/coinpay``).
3. ``npx``, ``bunx``, ``pnpm dlx`` or ``deno run``, whichever is installed.

``$COINPAY_VERSION`` pins the npm version (default: whatever npx resolves).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

PACKAGE = "@profullstack/coinpay"
__version__ = "0.1.0"


def _spec() -> str:
    v = os.environ.get("COINPAY_VERSION")
    return f"{PACKAGE}@{v}" if v else PACKAGE


def _real_cli() -> str | None:
    me = os.path.realpath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    for candidate in [p for p in (shutil.which("coinpay"),) if p]:
        if os.path.realpath(candidate) != me:
            return candidate
    return None


def command(args: list[str]) -> list[str] | None:
    exe = os.environ.get("COINPAY_BIN")
    if exe:
        return [exe, *args]
    real = _real_cli()
    if real:
        return [real, *args]
    if shutil.which("npx"):
        return ["npx", "--yes", _spec(), *args]
    if shutil.which("bunx"):
        return ["bunx", _spec(), *args]
    if shutil.which("pnpm"):
        return ["pnpm", "dlx", _spec(), *args]
    if shutil.which("deno"):
        return ["deno", "run", "-A", f"npm:{_spec()}", *args]
    return None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = command(args)
    if cmd is None:
        sys.stderr.write(
            "coinpay: the CoinPay CLI runs on Node.js 20+ (or Bun or Deno), and none was found.\n"
            "  Install Node from https://nodejs.org, then either run this command again\n"
            "  or install the CLI directly: npm install -g @profullstack/coinpay\n"
        )
        return 127
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        sys.stderr.write(f"coinpay: could not run {cmd[0]}: {e}\n")
        return 126


if __name__ == "__main__":
    sys.exit(main())
