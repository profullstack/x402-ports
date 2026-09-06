# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name = "coinpay"
  s.version = "0.1.0"
  s.summary = "The CoinPay CLI (coinpay x402 pay, checkout, wallets) from RubyGems."
  s.description = "A thin launcher for @profullstack/coinpay on npm: runs an installed coinpay, or fetches the CLI through npx, bunx, pnpm dlx or deno. Node.js 20+, Bun or Deno required."
  s.authors = ["Profullstack, LLC"]
  s.license = "MIT"
  s.homepage = "https://github.com/profullstack/x402-ports"
  s.metadata = { "source_code_uri" => "https://github.com/profullstack/x402-ports/tree/main/ruby/coinpay", "rubygems_mfa_required" => "true" }
  s.files = Dir["lib/**/*.rb", "exe/*", "README.md"]
  s.bindir = "exe"
  s.executables = ["coinpay"]
  s.require_paths = ["lib"]
  s.required_ruby_version = ">= 3.0"
end
