# x402gateway for Go

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A Go port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures. Standard library only.

```
go get github.com/profullstack/x402-ports/go/x402gateway
```

## net/http (also chi, gorilla, echo's WrapMiddleware, gin's WrapH)

```go
gw, err := x402gateway.New(x402gateway.Options{
    SiteURL:       "https://your-site.com",
    CoinPayAPIKey: os.Getenv("COINPAY_X402_KEY"), // a SCOPED CoinPay key (cp_live_…)
    PayTo:         os.Getenv("CRAWL_PAY_TO"),     // EVM address that receives the USDC
})
mux := http.NewServeMux()
mux.Handle("/robots.txt", gw.RobotsHandler(x402gateway.RobotsOptions{Disallow: []string{"/login", "/api/"}}))
mux.Handle("/", site)
http.ListenAndServe(":8080", gw.Middleware(mux))
```

## Anything else

`gw.Handle(r *http.Request)` returns an `*Answer` (status, headers, body) to send, or nil to carry on. `answer.Write(w)` sends it.

## Options

Same names as the reference, in Go casing: `PriceCents` (100), `PassMinutes` (1440), `MaxDays` (30), `Header` (`x-crawl-pass`), `Path` (`/crawl`), `OpenPaths`, `IsPaidAgent`, `DenyCIDRs`, `ChargeSpoofedBrowsers`, `Exempt func(*http.Request) bool`, `Secret`, `Page`, `Contact`, `OnSale`, `HTTPClient`. Without `CoinPayAPIKey` and `PayTo` the gateway still answers training crawlers with 402 and the page says payments are off.

## coinpay launcher

```
go install github.com/profullstack/x402-ports/go/cmd/coinpay@latest
coinpay x402 pay https://rssamplifier.com/crawl --output pass.json
```

Runs the CoinPay CLI (`@profullstack/coinpay` on npm) through an installed `coinpay`, `npx`, `bunx`, `pnpm dlx` or `deno`. Node.js 20+, Bun or Deno is required.

## Test

```
go test ./...
```
