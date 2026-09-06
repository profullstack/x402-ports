# x402-gateway (Rust)

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A Rust port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures.

Works on [`http`](https://crates.io/crates/http) types, so it fits axum, hyper, tower and anything built on them. CoinPay is reached over `ureq` (default feature) or any `Transport` you implement.

```
cargo add x402-gateway --features axum
```

## axum

```rust
use std::sync::Arc;
use x402_gateway::{Gateway, Options, RobotsOptions};

let gateway = Arc::new(Gateway::new(Options {
    site_url: "https://your-site.com".into(),
    coinpay_api_key: std::env::var("COINPAY_X402_KEY").unwrap_or_default(), // a SCOPED CoinPay key (cp_live_…)
    pay_to: std::env::var("CRAWL_PAY_TO").unwrap_or_default(),              // EVM address that receives the USDC
    ..Default::default()
})?);

let robots = gateway.clone();
let app = axum::Router::new()
    .route("/robots.txt", axum::routing::get(move || async move {
        robots.robots_txt(RobotsOptions { disallow: vec!["/login".into(), "/api/".into()], ..Default::default() })
    }))
    .fallback(site)
    .layer(axum::middleware::from_fn_with_state(gateway.clone(), x402_gateway::axum::gate));
```

## Anything else

`gateway.handle(&http::Request<B>)` returns `Option<http::Response<String>>`: `Some` to send, `None` to carry on. `handle_parts(path, query, &HeaderMap)` is the same without a request type.

## Options

Same names as the reference, snake_cased: `price_cents` (100), `pass_minutes` (1440), `max_days` (30), `header` (`x-crawl-pass`), `path` (`/crawl`), `open_paths`, `is_paid_agent`, `deny_cidrs`, `charge_spoofed_browsers`, `exempt: Fn(&HeaderMap) -> bool`, `secret`, `page`, `contact`, `on_sale`, `transport`. Without `coinpay_api_key` and `pay_to` the gateway still answers training crawlers with 402 and the page says payments are off.

## Test

```
cargo test
```
