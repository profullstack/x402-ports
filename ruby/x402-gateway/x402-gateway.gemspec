# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name = "x402-gateway"
  s.version = "0.1.0"
  s.summary = "Sell crawl access to AI training crawlers by the day over x402, settled by CoinPay."
  s.description = "Rack middleware: 402 with an x402 offer, a sales page, HMAC-signed passes and a robots.txt that keeps search crawlers welcome. A port of @profullstack/x402-gateway."
  s.authors = ["Profullstack, LLC"]
  s.license = "MIT"
  s.homepage = "https://github.com/profullstack/x402-ports"
  s.metadata = { "source_code_uri" => "https://github.com/profullstack/x402-ports/tree/main/ruby/x402-gateway", "rubygems_mfa_required" => "true" }
  s.files = Dir["lib/**/*.rb", "README.md"]
  s.require_paths = ["lib"]
  s.required_ruby_version = ">= 3.0"
end
