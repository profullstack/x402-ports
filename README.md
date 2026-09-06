# x402-ports

[@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway) in every language people run web servers in, plus the CoinPay CLI from every package manager. One repo, one fixture file, one CI.

The gateway sells crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). People, search engines and retrieval crawlers read free. GPTBot, ClaudeBot, CCBot, meta-externalagent and friends get `402 Payment Required` with an x402 offer, pay a dollar in USDC, and get an HMAC-signed pass that opens the site for a day. Every port here produces the same 402 body, the same pass format, the same robots.txt, and takes the same options as the JavaScript reference, snake_cased where the language wants it.

## The gateway

| Language | Install | Adapters | Directory |
| --- | --- | --- | --- |
| JavaScript (reference) | `npm i @profullstack/x402-gateway` | Hono, Next.js, Fetch `handle(request)` | [profullstack/x402-gateway](https://github.com/profullstack/x402-gateway) |
| Python | `pip install profullstack-x402-gateway` | ASGI (FastAPI, Starlette, Django), WSGI (Flask, Django) | [python/x402_gateway](python/x402_gateway) |
| Go | `go get github.com/profullstack/x402-ports/go/x402gateway` | `net/http` middleware | [go](go) |
| Rust | `cargo add x402-gateway --features axum` | `http` types, axum layer | [rust/x402-gateway](rust/x402-gateway) |
| Ruby | `gem install x402-gateway` | Rack (Rails, Sinatra, Roda, Hanami) | [ruby/x402-gateway](ruby/x402-gateway) |
| PHP | `composer require profullstack/x402-gateway` | PSR-15 (Slim, Mezzio), Laravel, plain PHP | [php/x402-gateway](php/x402-gateway) |
| Elixir | `{:x402_gateway, "~> 0.1"}` | Plug (Phoenix, Bandit) | [elixir/x402_gateway](elixir/x402_gateway) |
| Zig | `zig fetch --save <release tarball>` | `handle(arena, request)` | [zig](zig) |

Each port has zero runtime dependencies beyond the language's standard library (Rust: `http`, `hmac`, `sha2`, `serde_json`, `ureq`). Each is a few hundred lines and reads like the reference.

## The CoinPay CLI

`coinpay x402 pay https://site/crawl` is how a crawler buys a pass. The CLI is JavaScript ([@profullstack/coinpay](https://www.npmjs.com/package/@profullstack/coinpay)); these are launchers that run it through an installed `coinpay`, `npx`, `bunx`, `pnpm dlx` or `deno`, so it is one command away in whatever package manager is already on the machine. Node.js 20+, Bun or Deno is required.

| Package manager | Install | Directory |
| --- | --- | --- |
| pip | `pip install coinpay` | [python/coinpay](python/coinpay) |
| cargo | `cargo install coinpay` | [rust/coinpay](rust/coinpay) |
| gem | `gem install coinpay` | [ruby/coinpay](ruby/coinpay) |
| go | `go install github.com/profullstack/x402-ports/go/cmd/coinpay@latest` | [go/cmd/coinpay](go/cmd/coinpay) |
| composer | `composer global require profullstack/coinpay` | [php/coinpay](php/coinpay) |

`COINPAY_VERSION` pins the npm version; `COINPAY_BIN` points at a specific executable.

## One fixture file

[spec/vectors.json](spec/vectors.json) is generated from the JavaScript reference by [spec/gen-vectors.mjs](spec/gen-vectors.mjs): pass tokens minted with a fixed clock, 402 bodies, robots.txt output, CIDR and spoof decisions, 28 gateway decision cases, and a mocked CoinPay verify/settle flow with replay. Every port's test suite loads that file. A pass minted in Ruby is read by Go; a robots.txt from Python matches Rust byte for byte.

```
cd spec && npm install && npm run gen     # after bumping the reference version in spec/package.json
```

## Releasing

Each package is tagged on its own: `python-v0.1.0`, `rust-v0.1.0`, `ruby-v0.1.0`, `elixir-v0.1.0`, `zig-v0.1.0`, `go/v0.1.0`. The workflows in [.github/workflows](.github/workflows) build and publish on those tags. PyPI, crates.io and RubyGems use trusted publishing (OIDC), which needs a one-time setup on each registry pointing at this repo and the workflow file. Hex needs `HEX_API_KEY`. Go needs nothing but the tag. Zig gets a tarball on the GitHub release. Packagist requires a `composer.json` at a repository root, so the two PHP packages need a read-only split mirror each; the `split-php` workflow does that when `PHP_SPLIT_TOKEN` is set.

## Licence

MIT
