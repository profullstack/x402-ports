# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/coinpay"

class LauncherTest < Minitest::Test
  def with_env(vars)
    old = vars.keys.to_h { |k| [k, ENV.fetch(k, nil)] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  def test_env_bin_wins
    with_env("COINPAY_BIN" => "/opt/coinpay") { assert_equal %w[/opt/coinpay x402 pay u], Coinpay.command(%w[x402 pay u]) }
  end

  def test_nothing_found
    with_env("COINPAY_BIN" => nil, "PATH" => "/nonexistent") do
      assert_nil Coinpay.command([])
      assert_equal 127, Coinpay.main([])
    end
  end

  def test_pinned_version
    with_env("COINPAY_VERSION" => "0.8.0") { assert_equal "@profullstack/coinpay@0.8.0", Coinpay.spec }
  end
end
