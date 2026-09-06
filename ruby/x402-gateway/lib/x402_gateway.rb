# frozen_string_literal: true

# Sell crawl access to AI training crawlers, by the day, over x402, settled by CoinPay.
#
# A port of @profullstack/x402-gateway: the same 402 body, the same signed pass
# (cp_<payload>.<hmac>), the same robots.txt, the same order of decisions,
# checked against the same fixtures.
#
#   gateway = X402Gateway::Gateway.new(site_url: "https://your-site.com",
#                                      coinpay_api_key: ENV["COINPAY_X402_KEY"], pay_to: ENV["CRAWL_PAY_TO"])
#   use X402Gateway::Rack, gateway
require_relative "x402_gateway/core"
require_relative "x402_gateway/page"
require_relative "x402_gateway/rack"

module X402Gateway
  VERSION = "0.1.0"
end
