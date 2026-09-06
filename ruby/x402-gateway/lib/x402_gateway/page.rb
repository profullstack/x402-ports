# frozen_string_literal: true

require "cgi"

module X402Gateway
  CSS = <<~CSS
    :root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fff;--mut:#666;--line:#e5e5e5;--code:#f4f4f4;--acc:#0a5}
    @media(prefers-color-scheme:dark){:root{--fg:#eee;--bg:#111;--mut:#aaa;--line:#333;--code:#1c1c1c;--acc:#3c9}}
    body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
    main{max-width:44rem;margin:0 auto;padding:2.5rem 1.25rem 4rem}
    h1{font-size:1.8rem;line-height:1.2;margin:0 0 .5rem}h2{font-size:1.15rem;margin:2rem 0 .5rem}
    p{margin:.5rem 0}.mut{color:var(--mut)}
    pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:.9rem 1rem;overflow-x:auto;font-size:.88rem;line-height:1.45}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
    ol,ul{padding-left:1.3rem}li{margin:.3rem 0}
    .price{font-size:2.2rem;font-weight:700;color:var(--acc);margin:.25rem 0}
    table{border-collapse:collapse;margin:.5rem 0;font-size:.95rem}td,th{border-bottom:1px solid var(--line);padding:.35rem .6rem;text-align:left}
    footer{margin-top:3rem;color:var(--mut);font-size:.85rem}
  CSS

  module_function

  def window_for(minutes)
    return "one day" if minutes == 1440
    return "#{minutes / 1440} days" if (minutes % 1440).zero?
    return "one hour" if minutes == 60
    return "#{minutes / 60} hours" if (minutes % 60).zero?

    "#{minutes} minutes"
  end

  # The sales page: what a refused crawler is shown, and what its operator reads.
  def render_page(c)
    e = ->(s) { CGI.escapeHTML(s.to_s) }
    days = c[:days] || 1
    window = window_for(c[:minutes])
    networks = (c[:offer]["accepts"] || []).map { |a| a["network"] }.join(", ")
    networks = "Base, Polygon or Ethereum" if networks.empty?
    amount = days > 1 ? c[:total] : c[:price]
    span = days > 1 ? "#{days} × #{window}" : window
    more = if days > 1
             "<p class=\"mut\">This offer is for #{days} days at #{e.call(c[:price])} a day. The plain page at <code>#{e.call(c[:buy_url])}</code> quotes one.</p>"
           else
             "<p class=\"mut\">Want longer? Add <code>?days=&lt;n&gt;</code> to this URL for an offer of up to #{c[:max_days]} days at #{e.call(c[:price])} a day, or simply pay a whole multiple of the price: the pass lasts as many days as you paid for.</p>"
           end
    off = c[:enabled] ? "" : "<p><strong>Payments are not switched on here yet.</strong> The offer below is empty until the operator configures a payout address, so for now this crawler is simply refused.</p>"
    touch = c[:contact].to_s.empty? ? ", contact the site" : ", <a href=\"#{e.call(c[:contact])}\">get in touch</a>"
    <<~HTML
      <!doctype html>
      <html lang="en">
      <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <meta name="robots" content="noindex">
      <title>Crawl access · #{e.call(c[:site_name])}</title>
      <style>#{CSS}</style>
      </head>
      <body>
      <main>
      <h1>Training crawlers pay for access here.</h1>
      <p class="mut">People read <a href="#{e.call(c[:site_url])}">#{e.call(c[:site_name])}</a> free. So do search engines and the retrieval crawlers behind AI answers, because they send readers back. A crawler that copies pages into a training corpus sends nobody back, so it pays for the time it spends.</p>

      <div class="price">#{e.call(amount)} <span class="mut" style="font-size:1rem;font-weight:400">for #{e.call(span)} of requests</span></div>
      #{more}
      #{off}

      <h2>How it works</h2>
      <ol>
        <li>Any page you fetch answers <code>402 Payment Required</code>. This page, fetched with <code>Accept: application/json</code>, returns the x402 offer: USDC, <code>exact</code> scheme, on #{e.call(networks)}.</li>
        <li>Sign the payment and retry with the proof in an <code>X-PAYMENT</code> header. The response is a JSON receipt carrying a pass.</li>
        <li>Send the pass in <code>#{e.call(c[:header])}</code> on every request until it expires, #{e.call(window)} per day paid, so a proof for three times the price buys three. When it expires, buy another. The sale is the pass, not the page: fetch the page again with the pass.</li>
      </ol>

      <h2>Pay with the CoinPay CLI</h2>
      <p>Settlement is by CoinPay: the buyer's USDC goes straight to the site's wallet and CoinPay's relayer pays the gas, so you need USDC and nothing else.</p>
      <pre><code>npm install -g @profullstack/coinpay
      coinpay x402 pay #{e.call(c[:buy_url])} --output pass.json
      # or a week at once:
      coinpay x402 pay "#{e.call(c[:buy_url])}?days=7" --output pass.json</code></pre>
      <p>The command fetches this page, reads the offer, opens a browser tab to approve the payment with the CoinPay Wallet extension or any EIP-6963 wallet (MetaMask, Rabby, Coinbase Wallet), and writes the receipt to <code>pass.json</code>. Then:</p>
      <pre><code>PASS=$(node -p "require('./pass.json').pass")
      curl -H "#{e.call(c[:header])}: $PASS" #{e.call(c[:site_url])}/</code></pre>

      <h2>Pay from your own x402 client</h2>
      <pre><code>curl -sS -H "Accept: application/json" #{e.call(c[:buy_url])}
      # 402 with { "x402Version": 2, "accepts": [ ... ] }
      # sign an EIP-3009 transferWithAuthorization for one entry, then:
      curl -sS -H "X-PAYMENT: &lt;base64 proof&gt;" #{e.call(c[:buy_url])}
      # 200 with { "ok": true, "pass": "cp_...", "expires_at": "...", "days": 1, "header": "#{e.call(c[:header])}" }</code></pre>
      <p class="mut">The days a proof buys are read off the value it authorizes: a whole multiple of the one-day amount, up to #{c[:max_days]}. <code>?days=&lt;n&gt;</code> only changes what the offer quotes, so a standard client that pays exactly what is asked gets <em>n</em> days.</p>
      <p class="mut">The proof is x402 v2 in CoinPay's dialect: <code>{ x402Version: 2, scheme: "exact", network: "&lt;CAIP-2&gt;", payload: { signature, authorization } }</code>, base64-encoded. A proof is single-use; retrying with the same one returns the same pass, not a second charge.</p>

      <h2>Who pays and who does not</h2>
      <table>
      <tr><th>Charged</th><td>#{c[:training].map(&e).join(', ')}</td></tr>
      <tr><th>Free, named in robots.txt</th><td>#{c[:retrieval].map(&e).join(', ')}</td></tr>
      <tr><th>Free</th><td>Everyone else: people, Googlebot, Applebot, Bingbot and any crawler not on the first line.</td></tr>
      </table>
      <p class="mut">If your crawler is on the first line and you believe it should not be, or you want more than a day at a time#{touch}.</p>

      <footer>Sold over <a href="https://x402.org">x402</a>, settled by <a href="https://coinpayportal.com">CoinPay</a>. Served by x402-gateway for Ruby.</footer>
      </main>
      </body>
      </html>
    HTML
  end
end
