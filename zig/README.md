# x402_gateway (Zig)

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A Zig 0.16 port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures. Standard library only.

Zig has no registry, so fetch the tarball attached to a release of this monorepo:

```
zig fetch --save https://github.com/profullstack/x402-ports/releases/download/zig-v0.1.0/x402_gateway-zig-0.1.0.tar.gz
```

then in `build.zig`: `exe.root_module.addImport("x402_gateway", b.dependency("x402_gateway", .{}).module("x402_gateway"));`

## Use

```zig
const x402 = @import("x402_gateway");

var gateway = try x402.Gateway.init(gpa, .{
    .site_url = "https://your-site.com",
    .coinpay_api_key = coinpay_key, // a SCOPED CoinPay key (cp_live_…)
    .pay_to = pay_to,               // EVM address that receives the USDC
    .io = io,                       // your std.Io, for the clock
    .transport = .{ .ctx = &my_http, .post = MyHttp.post }, // your HTTP client, for CoinPay's verify and settle
});

// per request, with an arena you free afterwards:
if (try gateway.handle(arena, .{ .path = path, .query = query, .headers = headers })) |answer| {
    // send answer.status, content-type answer.content_type, the two headers in x402.Response.no_store,
    // answer.pass / answer.pass_expires as `<header>` / `<header>-expires` on a 200, and answer.body
} else {
    // serve the page
}
```

`gateway.robots(arena, .{ .disallow = &.{ "/login", "/api/" } })` writes robots.txt; `gateway.page(arena)` renders the sales page.

## What is different here

- CoinPay is reached through the `Transport` you pass: a function pointer over your own HTTP client (`std.http.Client` needs your `std.Io`). Without one, a proof is answered 402 with "No CoinPay transport configured."
- Proof values are read into `u128`. Anything larger is refused, never mis-read.
- The sales page is a shorter version of the reference's, with the same facts.

## Test

```
zig build test
```

Reads `../spec/vectors.json` from the monorepo root.
