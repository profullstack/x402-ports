# profullstack/x402-gateway (PHP)

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A PHP port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures. PHP 8.1+, no dependencies.

```
composer require profullstack/x402-gateway
```

## Laravel

```php
// app/Providers/AppServiceProvider.php
$this->app->singleton(Gateway::class, fn () => new Gateway([
    'site_url' => 'https://your-site.com',
    'coinpay_api_key' => env('COINPAY_X402_KEY'),  // a SCOPED CoinPay key (cp_live_…)
    'pay_to' => env('CRAWL_PAY_TO'),               // EVM address that receives the USDC
]));
// bootstrap/app.php
->withMiddleware(fn ($m) => $m->prepend(\Profullstack\X402Gateway\LaravelMiddleware::class))
// routes/web.php
Route::get('/robots.txt', fn (Gateway $g) => response($g->robotsTxt(['disallow' => ['/login', '/api/']]), 200, ['content-type' => 'text/plain']));
```

## Slim, Mezzio, any PSR-15 stack

```php
$app->add(new \Profullstack\X402Gateway\Psr15Middleware($gateway, $app->getResponseFactory()));
```

## Plain PHP

```php
if ($gateway->handleGlobals()) { exit; }   // top of index.php
```

## Anything else

`$gateway->handle(new Request($url, $lowercasedHeaders))` returns a `Response` (status, headers, body) or `null` to carry on.

## Options

An array with the reference's names in snake_case: `price_cents` (100), `pass_minutes` (1440), `max_days` (30), `header` (`x-crawl-pass`), `path` (`/crawl`), `open_paths`, `is_paid_agent`, `deny_cidrs`, `charge_spoofed_browsers`, `exempt` (a callable over the Request), `secret`, `page`, `contact`, `on_sale`. Without `coinpay_api_key` and `pay_to` the gateway still answers training crawlers with 402 and the page says payments are off. `ext-bcmath` or `ext-gmp` lets the gateway read proofs whose value exceeds 64 bits; without either such a proof is refused, never mis-read.

## Test

```
composer test
```
