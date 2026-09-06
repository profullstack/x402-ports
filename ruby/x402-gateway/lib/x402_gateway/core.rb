# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "uri"
require "time"

module X402Gateway
  # Training-only crawlers: refused in robots.txt, charged by the gateway.
  TRAINING_AGENTS = %w[GPTBot ClaudeBot anthropic-ai CCBot meta-externalagent FacebookBot Bytespider Applebot-Extended].freeze
  # Retrieval crawlers, named in robots.txt so their operators can see they are welcome.
  RETRIEVAL_AGENTS = %w[OAI-SearchBot ChatGPT-User Claude-SearchBot Claude-User PerplexityBot Perplexity-User Google-Extended Bingbot].freeze

  # What CoinPay can settle under the exact scheme: USDC on three chains, Base first.
  METHODS = [
    { key: "usdc_base", network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", label: "USDC on Base" },
    { key: "usdc_polygon", network: "eip155:137", asset: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", label: "USDC on Polygon" },
    { key: "usdc_eth", network: "eip155:1", asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", label: "USDC on Ethereum" }
  ].freeze
  DECIMALS = 6

  module_function

  # Whether a user agent names one of +agents+ (substring, case-insensitive).
  def training_agent?(user_agent, agents = TRAINING_AGENTS)
    ua = user_agent.to_s.downcase
    return false if ua.empty?

    agents.any? { |a| ua.include?(a.downcase) }
  end

  # A v2 402 body. +amount+ is the price in the token's smallest unit, rounded up.
  def build_offer(pay_to:, price_cents:, resource:, description: "Payment required", max_timeout_seconds: 300, methods: METHODS)
    raise ArgumentError, "an offer needs a payTo address" if pay_to.nil? || pay_to.empty?

    amount = ((price_cents.to_f / 100) * (10**DECIMALS)).ceil.to_s
    {
      "x402Version" => 2,
      "accepts" => methods.map do |m|
        {
          "scheme" => "exact", "network" => m[:network], "amount" => amount, "asset" => m[:asset], "payTo" => pay_to,
          "resource" => resource, "description" => description, "mimeType" => "application/json",
          "maxTimeoutSeconds" => max_timeout_seconds, "extra" => { "name" => "USD Coin", "version" => "2" }
        }
      end
    }
  end

  # base64 or base64url to text, the forgiving way atob reads it. Nil if it is not base64.
  def from_base64(s)
    t = s.to_s.gsub(/\s+/, "").tr("-_", "+/")
    t = t.sub(/=+\z/, "") if (t.length % 4).zero?
    return nil if t.length % 4 == 1 || t !~ %r{\A[A-Za-z0-9+/]*={0,2}\z}

    Base64.strict_decode64(t.sub(/=+\z/, "") + "=" * ((4 - t.length % 4) % 4)).force_encoding("UTF-8")
  rescue ArgumentError
    nil
  end

  # The proof out of an X-PAYMENT header: a Hash or Array, else nil.
  def decode_payment(header)
    return nil if header.nil? || header.empty?

    text = from_base64(header)
    return nil unless text && text.valid_encoding?

    parsed = JSON.parse(text)
    parsed.is_a?(Hash) || parsed.is_a?(Array) ? parsed : nil
  rescue JSON::ParserError
    nil
  end

  def dig(obj, *path)
    path.each do |k|
      return nil unless obj.is_a?(Hash)

      obj = obj[k]
    end
    obj
  end

  # What CoinPay must hold the proof to, from the OFFERED entry for its network.
  def expected_for(payment, offer)
    network = dig(payment, "network").to_s.downcase
    entry = (offer["accepts"] || []).find { |a| a["network"].downcase == network }
    return nil unless entry

    { "amount" => entry["amount"], "resource" => entry["resource"], "payTo" => entry["payTo"], "asset" => entry["asset"] }
  end

  def nonce_of(payment)
    v = dig(payment, "payload", "authorization", "nonce")
    v.nil? ? nil : v.to_s
  end

  def valid_before_of(payment)
    v = Float(dig(payment, "payload", "authorization", "validBefore").to_s.strip)
    v.finite? && v.positive? ? v.to_i : nil
  rescue ArgumentError, TypeError
    nil
  end

  # What BigInt(raw) would read: decimal or 0x strings, whole numbers.
  def bigint(raw)
    case raw
    when Integer then raw
    when Float then raw.finite? && raw == raw.floor ? raw.to_i : nil
    when String
      s = raw.strip
      if s =~ /\A[+-]?\d+\z/ then s.to_i
      elsif s =~ /\A0[xX][0-9a-fA-F]+\z/ then s[2..].to_i(16)
      end
    end
  end

  # The value a proof authorizes, in the token's smallest unit, or nil.
  def paid_value_of(payment)
    raw = dig(payment, "payload", "authorization", "value")
    return nil if raw.nil? || raw == ""

    v = bigint(raw)
    v && v.positive? ? v : nil
  end

  # How many terms +value+ buys at +unit+ per term: a whole number in [1, max_days], else 0.
  def days_paid(value, unit, max_days)
    return 0 if value.nil?

    per = bigint(unit)
    return 0 if per.nil? || per <= 0 || (value % per) != 0

    days = value / per
    days < 1 || days > max_days ? 0 : days
  end

  def b64url(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end

  def sign(secret, data)
    b64url(OpenSSL::HMAC.digest("SHA256", secret.to_s, data))
  end

  # Mint a pass: { token:, expires_at:, ref: }.
  def mint_pass(secret:, ref:, expires_at:, now: Time.now.to_i)
    raise ArgumentError, "a pass needs a signing secret" if secret.nil? || secret.empty?
    raise ArgumentError, "a pass needs a future expiry" if expires_at.nil? || expires_at <= now

    payload = b64url(JSON.generate({ "v" => 1, "iat" => now, "exp" => expires_at.to_i, "ref" => ref }))
    { token: "cp_#{payload}.#{sign(secret, payload)}", expires_at: expires_at.to_i, ref: ref }
  end

  # The claims when the signature holds and the pass is live, else nil. Never raises on garbage.
  def read_pass(token, secret:, now: Time.now.to_i)
    return nil if secret.nil? || secret.empty? || !token.is_a?(String) || !token.start_with?("cp_")

    dot = token.index(".")
    return nil unless dot

    payload = token[3...dot]
    sig = token[(dot + 1)..]
    return nil if payload.empty? || sig.empty?

    expect = sign(secret, payload)
    return nil unless expect.bytesize == sig.bytesize && OpenSSL.fixed_length_secure_compare(expect, sig)

    claims = JSON.parse(Base64.urlsafe_decode64(payload.sub(/=+\z/, "") + "=" * ((4 - payload.length % 4) % 4)))
    return nil unless claims.is_a?(Hash) && claims["v"] == 1
    exp = claims["exp"]
    return nil unless exp.is_a?(Numeric) && (!exp.is_a?(Float) || exp.finite?)
    return nil if exp <= now

    { "exp" => exp, "iat" => claims["iat"], "ref" => claims["ref"] }
  rescue ArgumentError, JSON::ParserError
    nil
  end

  def ipv4_to_int(ip)
    parts = ip.to_s.split(".", -1)
    return nil unless parts.length == 4

    n = 0
    parts.each do |p|
      return nil unless p =~ /\A\d{1,3}\z/
      v = p.to_i
      return nil if v > 255

      n = n * 256 + v
    end
    n
  end

  # "a.b.c.d/len" or a bare address -> [base, mask, text]. Nil if unreadable.
  def parse_cidr(cidr)
    s = cidr.to_s.strip
    ip, len_raw = s.split("/", 2)
    base = ipv4_to_int(ip)
    return nil if base.nil?

    if len_raw.nil?
      length = 32
    else
      return nil unless len_raw =~ /\A\d+\z/
      length = len_raw.to_i
      return nil if length > 32
    end
    mask = length.zero? ? 0 : (0xffffffff << (32 - length)) & 0xffffffff
    [base & mask, mask, "#{ip}/#{length}"]
  end

  def compile_cidrs(list)
    Array(list).map { |c| parse_cidr(c) }.compact
  end

  def in_cidrs?(ip, compiled)
    n = ipv4_to_int(ip.to_s.strip)
    return false if n.nil?

    compiled.any? { |base, mask, _| (n & mask) == base }
  end

  # The caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop.
  def client_ip(request)
    real = request.header("x-real-ip").to_s.strip
    return real unless real.empty?

    xff = request.header("x-forwarded-for")
    return "" if xff.nil?

    hops = xff.split(",").map(&:strip).reject(&:empty?)
    hops.last || ""
  end

  CLAIMS_CHROMIUM = %r{\bChrome/\d+}.freeze
  DECLARES_ITSELF = %r{compatible;|\bbot\b|bot/|crawler|spider|slurp}i.freeze

  # Claims Chromium, declares no crawler, sends no Sec-Fetch-Mode: an HTTP client with a copied string.
  def spoofed_browser?(request)
    ua = request.header("user-agent").to_s
    return false unless CLAIMS_CHROMIUM.match?(ua)
    return false if DECLARES_ITSELF.match?(ua)

    request.header("sec-fetch-mode").nil?
  end

  # robots.txt with the crawlers sorted the way the gateway sorts them.
  def robots_txt(site_url:, disallow: [], allow: [], sitemap: :default, path: "/crawl", refused: [],
                 training: TRAINING_AGENTS, retrieval: RETRIEVAL_AGENTS, comments: [])
    raise ArgumentError, "robots_txt needs site_url" if site_url.nil? || site_url.empty?

    base = site_url.sub(%r{/+\z}, "")
    map = sitemap == :default ? "#{base}/sitemap.xml" : sitemap.to_s
    welcome = ->(agent) { (["User-agent: #{agent}", "Allow: /"] + allow.map { |p| "Allow: #{p}" } + disallow.map { |p| "Disallow: #{p}" }).join("\n") }
    refuse = ->(agent) { "User-agent: #{agent}\nDisallow: /" }
    charge = ->(agent) { "#{refuse.call(agent)}\nAllow: #{path}" }
    lines = comments.map { |c| "# #{c}" }
    lines << "" unless comments.empty?
    lines.concat(refused.map { |a| "#{refuse.call(a)}\n" })
    lines.concat(training.map { |a| "#{charge.call(a)}\n" })
    lines.concat(retrieval.map { |a| "#{welcome.call(a)}\n" })
    lines << welcome.call("*") << ""
    lines.push("Sitemap: #{map}", "") unless map.empty?
    lines.join("\n")
  end

  # POST JSON to CoinPay: returns [status, body_text]. A transport error is [0, ""].
  def net_http_post(url, headers, body)
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.open_timeout = 20
    http.read_timeout = 20
    req = Net::HTTP::Post.new(uri.request_uri, headers)
    req.body = body
    res = http.request(req)
    [res.code.to_i, res.body.to_s]
  rescue StandardError
    [0, ""]
  end

  def parse_obj(text)
    v = JSON.parse(text)
    v.is_a?(Hash) ? v : {}
  rescue JSON::ParserError, TypeError
    {}
  end

  def truthy?(v)
    !(v.nil? || v == false || v == "" || v == 0)
  end

  # Verify, then settle. { ok: true, payer:, ref: } or { ok: false, reason:, replay: }.
  def verify_and_settle(payment, expected, api_key:, base_url:, post:)
    call = lambda do |path, body|
      status, text = post.call("#{base_url}#{path}", { "content-type" => "application/json", "x-api-key" => api_key }, JSON.generate(body))
      [status, parse_obj(text)]
    end
    vs, v = call.call("/api/x402/verify", { "payment" => payment, "expected" => expected })
    unless truthy?(v["valid"])
      reason = (v.key?("error") && !v["error"].nil? ? v["error"] : v.key?("reason") && !v["reason"].nil? ? v["reason"] : "verify failed (#{vs})").to_s
      return { ok: false, reason: reason, replay: reason.match?(/already used|replay/i) }
    end
    ss, s = call.call("/api/x402/settle", { "payment" => payment })
    unless truthy?(s["settled"])
      reason = (s.key?("error") && !s["error"].nil? ? s["error"] : "settle failed (#{ss})").to_s
      return { ok: false, reason: reason, replay: reason.match?(/already settled|already being settled/i) }
    end
    ref = s["txHash"]
    ref = nonce_of(payment) if ref.nil? || ref == ""
    { ok: true, payer: dig(v, "payment", "from"), ref: ref }
  end

  # Whether the proof has already been paid, when a settle is asked about twice.
  def settle_again(payment, api_key:, base_url:, post:)
    _, text = post.call("#{base_url}/api/x402/settle", { "content-type" => "application/json", "x-api-key" => api_key }, JSON.generate({ "payment" => payment }))
    s = parse_obj(text)
    truthy?(s["settled"]) || s["error"].to_s.match?(/already settled/i)
  end

  def wants_html?(accept)
    accept.to_s.downcase.include?("text/html")
  end

  # The little the gateway needs to know about a request. Header names are lower-cased.
  Request = Struct.new(:url, :headers, :method, keyword_init: true) do
    def header(name)
      headers[name.downcase]
    end

    def path
      p = URI(url).path
      p.nil? || p.empty? ? "/" : p
    end

    def query(name)
      q = URI(url).query
      return nil if q.nil?

      URI.decode_www_form(q).find { |k, _| k == name }&.last
    end
  end

  Response = Struct.new(:status, :headers, :body, keyword_init: true)

  # A gateway that sells crawl access to training crawlers, by the day, over x402.
  class Gateway
    NO_STORE = { "cache-control" => "no-store", "vary" => "Accept, User-Agent, X-Payment" }.freeze
    BEARER = /\ABearer\s+(cp_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\z/i.freeze

    attr_reader :site_url, :site_name, :header, :path, :price_cents, :currency, :pass_minutes, :max_days,
                :training, :retrieval, :enabled, :secret, :buy_url, :contact

    # See the README for every option; names match the reference, snake_cased.
    def initialize(site_url:, site_name: nil, coinpay_api_key: "", coinpay_base_url: "https://coinpayportal.com", pay_to: "",
                   price_cents: 100, currency: "USD", pass_minutes: 1440, max_days: 30, header: "x-crawl-pass", path: "/crawl",
                   open_paths: [], is_paid_agent: nil, deny_cidrs: [], charge_spoofed_browsers: false, exempt: nil, secret: "",
                   training: TRAINING_AGENTS, retrieval: RETRIEVAL_AGENTS, page: nil, contact: "", on_sale: nil,
                   post: X402Gateway.method(:net_http_post), now: -> { Time.now.to_i })
      @site_url = site_url.to_s.sub(%r{/+\z}, "")
      raise ArgumentError, "Gateway needs site_url" if @site_url.empty?

      @site_name = site_name || (URI(@site_url).host rescue nil) || @site_url
      @coinpay_api_key = coinpay_api_key.to_s
      @coinpay_base_url = coinpay_base_url.to_s.sub(%r{/+\z}, "")
      @pay_to = pay_to.to_s
      @price_cents = price_cents.is_a?(Numeric) ? price_cents : 100
      @currency = currency
      @pass_minutes = pass_minutes.is_a?(Integer) && pass_minutes.positive? ? pass_minutes : 1440
      @max_days = max_days.is_a?(Integer) && max_days >= 1 ? max_days : 30
      @header = (header.to_s.empty? ? "x-crawl-pass" : header.to_s).downcase
      @path = path.to_s.empty? ? "/crawl" : path
      @deny = X402Gateway.compile_cidrs(deny_cidrs)
      @charge_spoofed = charge_spoofed_browsers ? true : false
      @exempt = exempt
      @training = Array(training)
      @retrieval = Array(retrieval)
      @is_paid_agent = is_paid_agent || ->(ua) { X402Gateway.training_agent?(ua, @training) }
      @page = page || X402Gateway.method(:render_page)
      @contact = contact.to_s
      @on_sale = on_sale
      @post = post
      @now = now
      @enabled = !@coinpay_api_key.empty? && !@pay_to.empty?
      @secret = secret.to_s.empty? ? @coinpay_api_key : secret.to_s
      @open = ["/robots.txt", @path, "/security.txt", "/.well-known/"] + Array(open_paths)
      @buy_url = "#{@site_url}#{@path}"
    end

    def money(cents)
      "#{format('%.2f', cents / 100.0)} #{@currency}"
    end

    def price
      money(@price_cents)
    end

    # The offer for +days+ terms: the same entries, +days+ times the price.
    def offer(days = 1)
      return { "x402Version" => 2, "accepts" => [] } unless @enabled

      extra = days > 1 ? " (#{days} × #{@pass_minutes})" : ""
      X402Gateway.build_offer(pay_to: @pay_to, price_cents: @price_cents * days, resource: @buy_url,
                              description: "#{days * @pass_minutes} minutes of crawl access to #{@site_url}#{extra}")
    end

    def receipt(days = 1, extra = {})
      offer(days).merge(
        "pass" => {
          "price" => price, "minutes" => @pass_minutes, "days" => days, "total" => money(@price_cents * days),
          "maxDays" => @max_days, "header" => @header,
          "buy" => days > 1 ? "#{@buy_url}?days=#{days}" : @buy_url, "buyDays" => "#{@buy_url}?days=<n>"
        }
      ).merge(extra)
    end

    def page_ctx(days = 1)
      { days: days, total: money(@price_cents * days), site_name: @site_name, site_url: @site_url, buy_url: @buy_url,
        price: price, minutes: @pass_minutes, max_days: @max_days, header: @header, enabled: @enabled, offer: offer,
        training: @training, retrieval: @retrieval, contact: @contact }
    end

    # robots.txt with this gateway's lists and sales path.
    def robots_txt(**extra)
      X402Gateway.robots_txt(**{ site_url: @site_url, path: @path, training: @training, retrieval: @retrieval }.merge(extra))
    end

    # The sales page as HTML, for a site that mounts it on a route of its own.
    def page
      @page.call(page_ctx)
    end

    # Whether handling this request may call CoinPay (only a proof does).
    def needs_io?(request)
      !request.header("x-payment").nil?
    end

    # Answer one request with the sale: a pass as the body of a 200, or a 402 with the offer.
    def sell(request)
      ua = request.header("user-agent").to_s
      proof_header = request.header("x-payment")
      asked = days_from(request)

      if proof_header && !proof_header.empty?
        return json(receipt(asked, "error" => "Payments are not switched on here."), 402) unless @enabled

        payment = X402Gateway.decode_payment(proof_header)
        return json(receipt(asked, "error" => "X-PAYMENT is not base64 JSON."), 402) if payment.nil?

        unit = X402Gateway.expected_for(payment, offer(1))
        return json(receipt(asked, "error" => "Proof does not match an offered network."), 402) if unit.nil?

        days = X402Gateway.days_paid(X402Gateway.paid_value_of(payment), unit["amount"], @max_days)
        if days.zero?
          msg = "Pay a whole number of days: #{unit['amount']} per day in the token's smallest unit, up to #{@max_days} days. Add ?days=<n> to #{@buy_url} for the offer."
          return json(receipt(asked, "error" => msg), 402)
        end
        expected = X402Gateway.expected_for(payment, offer(days)) || unit
        term = days * @pass_minutes * 60
        now = @now.call.to_i
        cp = { api_key: @coinpay_api_key, base_url: @coinpay_base_url, post: @post }
        result = X402Gateway.verify_and_settle(payment, expected, **cp)

        expires_at = nil
        replayed = false
        if result[:ok]
          expires_at = now + term
        elsif result[:replay]
          paid = X402Gateway.settle_again(payment, **cp)
          valid_before = X402Gateway.valid_before_of(payment)
          if paid && valid_before
            expires_at = [now + term, valid_before + term].min
            replayed = true
          end
        end
        if expires_at.nil? || expires_at <= now
          return json(receipt(days, "error" => result[:reason] || "Payment could not be settled."), 402)
        end

        ref = X402Gateway.nonce_of(payment) || result[:ref]
        minted = X402Gateway.mint_pass(secret: @secret, ref: ref, expires_at: expires_at, now: now)
        expires = Time.at(minted[:expires_at]).utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if @on_sale && !replayed
          begin
            @on_sale.call(payer: result[:payer], ref: ref, token: minted[:token], expires_at: expires, user_agent: ua,
                          price_cents: @price_cents, days: days, total_cents: @price_cents * days, currency: @currency)
          rescue StandardError
            nil # accounting must never cost a buyer the pass
          end
        end
        return json(
          { "ok" => true, "pass" => minted[:token], "expires_at" => expires, "days" => days, "minutes" => days * @pass_minutes,
            "header" => @header, "replayed" => replayed, "use" => "curl -H \"#{@header}: #{minted[:token]}\" #{@site_url}/" },
          200, { @header => minted[:token], "#{@header}-expires" => expires }
        )
      end

      return html(@page.call(page_ctx(asked)), 402) if X402Gateway.wants_html?(request.header("accept"))

      json(receipt(asked, "error" => "Payment required for training crawlers. Read #{@buy_url} for how."), 402)
    end

    # The gate. Nil means "not for me, carry on".
    def handle(request)
      if !@deny.empty? && X402Gateway.in_cidrs?(X402Gateway.client_ip(request), @deny)
        return Response.new(status: 403, headers: { "content-type" => "text/plain; charset=utf-8" }.merge(NO_STORE), body: "Not available from this network.\n")
      end

      path = request.path
      return sell(request) if path == @path
      return nil if @exempt&.call(request)

      pays = @is_paid_agent.call(request.header("user-agent").to_s) || (@charge_spoofed && X402Gateway.spoofed_browser?(request))
      return nil unless pays
      return nil if open?(path)

      token = pass_from(request)
      return nil if token && X402Gateway.read_pass(token, secret: @secret, now: @now.call.to_i)

      sell(request)
    end

    private

    def open?(path)
      @open.any? { |p| p.end_with?("/") ? path.start_with?(p) : path == p }
    end

    def days_from(request)
      m = /\A\s*([+-]?\d+)/.match(request.query("days").to_s)
      n = m ? m[1].to_i : 0
      return 1 if n < 1

      [n, @max_days].min
    end

    def pass_from(request)
      direct = request.header(@header)
      return direct.strip if direct && !direct.empty?

      m = BEARER.match(request.header("authorization").to_s)
      m && m[1]
    end

    def json(body, status, extra = {})
      Response.new(status: status, headers: { "content-type" => "application/json; charset=utf-8" }.merge(NO_STORE).merge(extra),
                   body: JSON.pretty_generate(body))
    end

    def html(body, status)
      Response.new(status: status, headers: { "content-type" => "text/html; charset=utf-8" }.merge(NO_STORE), body: body)
    end
  end
end
