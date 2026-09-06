// Command coinpay launches the CoinPay CLI (@profullstack/coinpay on npm):
// go install github.com/profullstack/x402-ports/go/cmd/coinpay@latest
//
// Order: $COINPAY_BIN; a coinpay on PATH that is not this launcher; then npx,
// bunx, pnpm dlx or deno run. $COINPAY_VERSION pins the npm version.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const pkg = "@profullstack/coinpay"

func spec() string {
	if v := os.Getenv("COINPAY_VERSION"); v != "" {
		return pkg + "@" + v
	}
	return pkg
}

func realCLI() string {
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	p, err := exec.LookPath("coinpay")
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil && r == self {
		return ""
	}
	return p
}

func command(args []string) []string {
	if exe := os.Getenv("COINPAY_BIN"); exe != "" {
		return append([]string{exe}, args...)
	}
	if real := realCLI(); real != "" {
		return append([]string{real}, args...)
	}
	for _, r := range [][]string{{"npx", "--yes", spec()}, {"bunx", spec()}, {"pnpm", "dlx", spec()}, {"deno", "run", "-A", "npm:" + spec()}} {
		if _, err := exec.LookPath(r[0]); err == nil {
			return append(r, args...)
		}
	}
	return nil
}

func main() {
	cmd := command(os.Args[1:])
	if cmd == nil {
		fmt.Fprint(os.Stderr, "coinpay: the CoinPay CLI runs on Node.js 20+ (or Bun or Deno), and none was found.\n  Install Node from https://nodejs.org, then either run this command again\n  or install the CLI directly: npm install -g @profullstack/coinpay\n")
		os.Exit(127)
	}
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "coinpay: could not run %s: %v\n", cmd[0], err)
		os.Exit(126)
	}
}
