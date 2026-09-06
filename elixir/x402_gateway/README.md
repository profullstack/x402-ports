# x402_gateway (Elixir)

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). An Elixir port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures. Elixir 1.18+ (built-in `JSON`), `:httpc` for CoinPay, Plug optional.

```elixir
{:x402_gateway, "~> 0.1"}
```

## Phoenix / Plug

```elixir
# lib/my_app_web/endpoint.ex, before the router
plug X402Gateway.Plug,
  site_url: "https://your-site.com",
  coinpay_api_key: System.get_env("COINPAY_X402_KEY"),  # a SCOPED CoinPay key (cp_live_…)
  pay_to: System.get_env("CRAWL_PAY_TO")                # EVM address that receives the USDC

# router: robots.txt
get "/robots.txt", RobotsController, :show   # text(conn, X402Gateway.robots_txt(gateway, disallow: ["/login", "/api/"]))
```

Keep the gateway in config or a module attribute to share it between the plug and the robots route: `X402Gateway.new(...)` then `plug X402Gateway.Plug, gateway: @gateway`.

## Anything else

`X402Gateway.handle(gateway, %{url: url, headers: lowercased_map, method: "GET"})` returns `%{status, headers, body}` to send, or `nil` to carry on.

## Options

Same names as the reference, snake_cased: `price_cents` (100), `pass_minutes` (1440), `max_days` (30), `header` (`x-crawl-pass`), `path` (`/crawl`), `open_paths`, `is_paid_agent`, `deny_cidrs`, `charge_spoofed_browsers`, `exempt` (a fun over the request map), `secret`, `page`, `contact`, `on_sale`, `post`. Without `coinpay_api_key` and `pay_to` the gateway still answers training crawlers with 402 and the page says payments are off. JSON bodies are compact rather than pretty-printed; the content is identical.

## Test

```
mix deps.get && mix test
```
