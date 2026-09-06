# profullstack/coinpay (Composer)

The [CoinPay](https://coinpayportal.com) CLI from Composer. `coinpay x402 pay` buys a crawl pass from any site running [x402-gateway](https://github.com/profullstack/x402-gateway).

```
composer global require profullstack/coinpay
coinpay x402 pay https://rssamplifier.com/crawl --output pass.json
```

The CLI itself is [@profullstack/coinpay](https://www.npmjs.com/package/@profullstack/coinpay) on npm. This package is a launcher: it runs a `coinpay` already installed with npm, or fetches the CLI through `npx`, `bunx`, `pnpm dlx` or `deno run`. Node.js 20+, Bun or Deno is required. `COINPAY_VERSION` pins the npm version; `COINPAY_BIN` points at a specific executable.
