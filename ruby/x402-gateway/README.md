# x402-gateway (Ruby)

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A Ruby port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures. Standard library only. Rack 2 and 3.

```
gem install x402-gateway
```

## Rails

```ruby
# config/initializers/x402.rb
require "x402_gateway"
X402 = X402Gateway::Gateway.new(
  site_url: "https://your-site.com",
  coinpay_api_key: ENV["COINPAY_X402_KEY"],  # a SCOPED CoinPay key (cp_live_…)
  pay_to: ENV["CRAWL_PAY_TO"],               # EVM address that receives the USDC
)
Rails.application.config.middleware.insert_before 0, X402Gateway::Rack, X402

# config/routes.rb
get "/robots.txt", to: ->(env) { [200, { "content-type" => "text/plain" }, [X402.robots_txt(disallow: ["/login", "/api/"])]] }
```

## Sinatra, Roda, Hanami, config.ru

```ruby
use X402Gateway::Rack, gateway
```

## Anything else

`gateway.handle(X402Gateway::Request.new(url:, headers:))` returns an `X402Gateway::Response` (status, headers, body) to send, or `nil` to carry on. Header names are lower-cased.

## Options

Same names as the reference, snake_cased: `price_cents` (100), `pass_minutes` (1440), `max_days` (30), `header` (`x-crawl-pass`), `path` (`/crawl`), `open_paths`, `is_paid_agent`, `deny_cidrs`, `charge_spoofed_browsers`, `exempt` (a lambda over the request), `secret`, `page`, `contact`, `on_sale`. Without `coinpay_api_key` and `pay_to` the gateway still answers training crawlers with 402 and the page says payments are off.

## Test

```
ruby test/vectors_test.rb
```
