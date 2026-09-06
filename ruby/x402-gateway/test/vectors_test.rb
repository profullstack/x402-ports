# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "base64"
require_relative "../lib/x402_gateway"

V = JSON.parse(File.read(ENV["X402_VECTORS"] || File.expand_path("../../../spec/vectors.json", __dir__)))
C = V["constants"]
NOW = C["NOW"]
SITE = C["SITE"]

def gateway(post: nil, **extra)
  g = V["gateway"]
  sub = g["exempt"]
  X402Gateway::Gateway.new(
    site_url: g["siteUrl"], coinpay_api_key: g.dig("coinpay", "apiKey").to_s, pay_to: g["payTo"].to_s,
    deny_cidrs: g["denyCidrs"] || [], charge_spoofed_browsers: g["chargeSpoofedBrowsers"] || false, open_paths: g["openPaths"] || [],
    exempt: ->(r) { r.header("cookie").to_s.include?(sub) },
    now: -> { NOW }, post: post || ->(url, *) { raise "CoinPay must not be called: #{url}" }, **extra
  )
end

def req(c)
  X402Gateway::Request.new(url: SITE + c["url"], headers: c["headers"].transform_keys(&:downcase), method: "GET")
end

def robots_opts(i)
  o = { site_url: i["siteUrl"] }
  o[:disallow] = i["disallow"] if i["disallow"]
  o[:allow] = i["allow"] if i["allow"]
  o[:sitemap] = i["sitemap"] if i.key?("sitemap")
  o[:path] = i["path"] if i["path"]
  o[:refused] = i["refused"] if i["refused"]
  o[:training] = i["training"] if i["training"]
  o[:retrieval] = i["retrieval"] if i["retrieval"]
  o[:comments] = i["comments"] if i["comments"]
  o
end

class VectorsTest < Minitest::Test
  def test_passes
    V["passes"].each do |p|
      assert_equal p["token"], X402Gateway.mint_pass(secret: p["secret"], ref: p["ref"], expires_at: p["exp"], now: p["iat"])[:token]
    end
    V["readPass"].each do |c|
      r = X402Gateway.read_pass(c["token"], secret: c["secret"] || C["SECRET"], now: c["now"])
      assert_equal c["ok"], !r.nil?, c.to_s
      assert_equal c["claims"], r if c["ok"]
    end
  end

  def test_offers_and_payments
    V["offers"].each do |o|
      i = o["in"]
      got = X402Gateway.build_offer(pay_to: i["payTo"], price_cents: i["priceCents"], resource: i["resource"], description: i["description"],
                                    **(i["maxTimeoutSeconds"] ? { max_timeout_seconds: i["maxTimeoutSeconds"] } : {}))
      assert_equal o["out"], got
    end
    offer = V["offers"][0]["out"]
    V["payments"].each do |p|
      d = X402Gateway.decode_payment(p["header"])
      assert_equal p["decodes"], !d.nil?, p.to_s
      if p.key?("expected")
        got = X402Gateway.expected_for(d, offer)
        p["expected"].nil? ? assert_nil(got, p.to_s) : assert_equal(p["expected"], got, p.to_s)
      end
    end
    V["daysPaid"].each do |d|
      v = d["value"].nil? ? nil : X402Gateway.bigint(d["value"])
      v = nil if v && v <= 0
      assert_equal d["days"], X402Gateway.days_paid(v, d["unit"], d["maxDays"]), d.to_s
    end
  end

  def test_agents_edge_robots
    V["agents"].each { |a| assert_equal a["training"], X402Gateway.training_agent?(a["ua"]), a["ua"] }
    c = X402Gateway.compile_cidrs(V["cidrs"]["list"])
    assert_equal V["cidrs"]["compiled"], c.map(&:last)
    V["cidrs"]["cases"].each { |k| assert_equal k["hit"], X402Gateway.in_cidrs?(k["ip"], c), k["ip"] }
    n = X402Gateway.compile_cidrs(V["cidrs"]["narrow"]["list"])
    V["cidrs"]["narrow"]["cases"].each { |k| assert_equal k["hit"], X402Gateway.in_cidrs?(k["ip"], n), k["ip"] }
    V["clientIp"].each do |k|
      assert_equal k["ip"], X402Gateway.client_ip(X402Gateway::Request.new(url: "#{SITE}/", headers: k["headers"])), k.to_s
    end
    V["spoofs"].each do |s|
      r = X402Gateway::Request.new(url: "#{SITE}/", headers: { "user-agent" => s["ua"] }.merge(s["headers"]))
      assert_equal s["spoofed"], X402Gateway.spoofed_browser?(r), s["ua"]
    end
    V["robots"].each { |r| assert_equal r["out"], X402Gateway.robots_txt(**robots_opts(r["in"])) }
  end

  def check(gw, c)
    r = gw.handle(req(c))
    if c["pass"]
      assert_nil r, c["name"]
      return
    end
    refute_nil r, c["name"]
    assert_equal c["status"], r.status, c["name"]
    assert_equal c["contentType"], r.headers["content-type"].split(";").first, c["name"] if c["contentType"]
    assert_equal c["body"], JSON.parse(r.body), c["name"] if c.key?("body")
    assert_equal c["text"], r.body, c["name"] if c["text"]
    (c["htmlContains"] || []).each { |s| assert_includes r.body, s, c["name"] }
    (c["responseHeaders"] || {}).each { |k, v| assert_equal v, r.headers[k], "#{c['name']}: #{k}" }
  end

  def test_handle
    gw = gateway
    V["handle"].each { |c| check(gw, c) }
    d = X402Gateway::Gateway.new(site_url: SITE, now: -> { NOW })
    V["disabled"].each { |c| check(d, c) }
    assert_equal X402Gateway.robots_txt(site_url: SITE), gw.robots_txt
    assert_includes gw.page, "1.00 USD"
  end

  def test_rack
    gw = gateway
    app = X402Gateway::Rack.new(->(_env) { [200, { "content-type" => "text/plain" }, ["site"]] }, gw)
    env = { "REQUEST_METHOD" => "GET", "PATH_INFO" => "/", "QUERY_STRING" => "", "SCRIPT_NAME" => "", "rack.url_scheme" => "https",
            "HTTP_HOST" => "example.com", "HTTP_USER_AGENT" => "GPTBot" }
    status, headers, body = app.call(env)
    assert_equal 402, status
    assert_equal "application/json; charset=utf-8", headers["content-type"]
    assert_equal 2, JSON.parse(body.join)["x402Version"]
    assert_equal 200, app.call(env.merge("HTTP_USER_AGENT" => "curl/8")).first
  end

  def test_paid
    V["coinpay"]["paid"].each do |c|
      calls = []
      post = lambda do |url, headers, body|
        assert_equal C["SECRET"], headers["x-api-key"]
        calls << [url, JSON.parse(body)]
        settles = calls.count { |u, _| u.end_with?("/api/x402/settle") }
        out = if url.end_with?("/api/x402/verify") then c["verify"]
              elsif settles == 1 && c["settle"] then c["settle"]
              else c["settleAgain"] || c["settle"]
              end
        [200, JSON.generate(out)]
      end
      sales = []
      gw = gateway(post: post, on_sale: ->(s) { sales << s })
      r = gw.handle(X402Gateway::Request.new(url: "#{SITE}/crawl", headers: { "x-payment" => Base64.strict_encode64(JSON.generate(c["proof"])), "user-agent" => "curl/8" }))
      assert_equal c["status"], r.status, "#{c['name']}: #{r.body}"
      body = JSON.parse(r.body)
      if c["status"] == 200
        assert body["ok"]
        assert_equal c["days"], body["days"], c["name"]
        assert_equal c["minutes"], body["minutes"], c["name"] if c["minutes"]
        assert_equal c["replayed"], body["replayed"], c["name"]
        claims = X402Gateway.read_pass(body["pass"], secret: C["SECRET"], now: NOW)
        refute_nil claims
        assert_equal c["ref"], claims["ref"], c["name"] if c["ref"]
        assert_equal c["expiresAt"], claims["exp"], c["name"] if c["expiresAt"]
        assert_equal body["pass"], r.headers["x-crawl-pass"]
        assert_equal c["replayed"] ? 0 : 1, sales.length, c["name"]
        assert_equal (1_000_000 * c["days"]).to_s, calls[0][1]["expected"]["amount"]
      else
        assert_equal c["error"], body["error"], c["name"] if c["error"]
        assert_empty sales
      end
    end
  end
end
