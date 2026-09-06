defmodule X402Gateway do
  @moduledoc """
  Sell crawl access to AI training crawlers, by the day, over x402, settled by CoinPay.

  A port of `@profullstack/x402-gateway`: the same 402 body, the same signed pass
  (`cp_<payload>.<hmac>`), the same robots.txt, the same order of decisions,
  checked against the same fixtures.

      gateway = X402Gateway.new(site_url: "https://your-site.com",
                                coinpay_api_key: System.get_env("COINPAY_X402_KEY"),
                                pay_to: System.get_env("CRAWL_PAY_TO"))
      plug X402Gateway.Plug, gateway: gateway

  `handle/2` takes a request map (`%{url, headers, method}`, header names lower-cased)
  and returns `{:ok, %{status, headers, body}}` to send, or `nil` to carry on.
  """

  @training ~w(GPTBot ClaudeBot anthropic-ai CCBot meta-externalagent FacebookBot Bytespider Applebot-Extended)
  @retrieval ~w(OAI-SearchBot ChatGPT-User Claude-SearchBot Claude-User PerplexityBot Perplexity-User Google-Extended Bingbot)

  @methods [
    %{
      key: "usdc_base",
      network: "eip155:8453",
      asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      label: "USDC on Base"
    },
    %{
      key: "usdc_polygon",
      network: "eip155:137",
      asset: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
      label: "USDC on Polygon"
    },
    %{
      key: "usdc_eth",
      network: "eip155:1",
      asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      label: "USDC on Ethereum"
    }
  ]

  @doc "Training-only crawlers: refused in robots.txt, charged by the gateway."
  def training_agents, do: @training
  @doc "Retrieval crawlers, named in robots.txt so their operators can see they are welcome."
  def retrieval_agents, do: @retrieval
  def methods, do: @methods

  @doc "Whether a user agent names one of `agents` (substring, case-insensitive)."
  def training_agent?(user_agent, agents \\ @training) do
    ua = String.downcase(user_agent || "")
    ua != "" and Enum.any?(agents, &String.contains?(ua, String.downcase(&1)))
  end

  # ------------------------------------------------------------------ x402 --

  @doc "A v2 402 body. `amount` is the price in the token's smallest unit, rounded up."
  def build_offer(opts) do
    pay_to = Keyword.fetch!(opts, :pay_to)
    if pay_to in [nil, ""], do: raise(ArgumentError, "an offer needs a payTo address")
    price = Keyword.fetch!(opts, :price_cents) / 1
    amount = Integer.to_string(trunc(Float.ceil(price / 100 * 1_000_000)))

    %{
      "x402Version" => 2,
      "accepts" =>
        Enum.map(Keyword.get(opts, :methods, @methods), fn m ->
          %{
            "scheme" => "exact",
            "network" => m.network,
            "amount" => amount,
            "asset" => m.asset,
            "payTo" => pay_to,
            "resource" => Keyword.fetch!(opts, :resource),
            "description" => Keyword.get(opts, :description, "Payment required"),
            "mimeType" => "application/json",
            "maxTimeoutSeconds" => Keyword.get(opts, :max_timeout_seconds, 300),
            "extra" => %{"name" => "USD Coin", "version" => "2"}
          }
        end)
    }
  end

  @doc false
  def from_base64(s) do
    t =
      s
      |> to_string()
      |> String.replace(~r/\s+/, "")
      |> String.replace("-", "+")
      |> String.replace("_", "/")

    t = if rem(byte_size(t), 4) == 0, do: String.trim_trailing(t, "="), else: t

    cond do
      rem(byte_size(t), 4) == 1 ->
        nil

      not Regex.match?(~r/^[A-Za-z0-9+\/]*={0,2}$/, t) ->
        nil

      true ->
        t = String.trim_trailing(t, "=")

        case Base.decode64(t, padding: false) do
          {:ok, bin} -> bin
          :error -> nil
        end
    end
  end

  @doc "The proof out of an X-PAYMENT header: a map or list, else nil."
  def decode_payment(nil), do: nil
  def decode_payment(""), do: nil

  def decode_payment(header) do
    with bin when is_binary(bin) <- from_base64(header),
         true <- String.valid?(bin),
         {:ok, v} when is_map(v) or is_list(v) <- JSON.decode(bin) do
      v
    else
      _ -> nil
    end
  end

  defp dig(obj, []), do: obj
  defp dig(obj, [k | rest]) when is_map(obj), do: dig(Map.get(obj, k), rest)
  defp dig(_, _), do: nil

  defp str(nil), do: ""
  defp str(v) when is_binary(v), do: v
  defp str(v) when is_number(v) or is_boolean(v), do: to_string(v)
  defp str(_), do: ""

  @doc "What CoinPay must hold the proof to, from the OFFERED entry for its network."
  def expected_for(payment, offer) do
    network = payment |> dig(["network"]) |> str() |> String.downcase()

    case Enum.find(offer["accepts"] || [], &(String.downcase(&1["network"]) == network)) do
      nil ->
        nil

      a ->
        %{
          "amount" => a["amount"],
          "resource" => a["resource"],
          "payTo" => a["payTo"],
          "asset" => a["asset"]
        }
    end
  end

  def nonce_of(payment) do
    case dig(payment, ["payload", "authorization", "nonce"]) do
      nil -> nil
      v -> str(v)
    end
  end

  def valid_before_of(payment) do
    case payment
         |> dig(["payload", "authorization", "validBefore"])
         |> str()
         |> String.trim()
         |> Float.parse() do
      {f, ""} when f > 0 -> trunc(f)
      _ -> nil
    end
  end

  @doc "What `BigInt(raw)` would read: decimal or 0x strings, whole numbers. nil otherwise."
  def bigint(raw) when is_integer(raw), do: raw
  def bigint(raw) when is_float(raw), do: if(raw == Float.floor(raw), do: trunc(raw), else: nil)

  def bigint(raw) when is_binary(raw) do
    s = String.trim(raw)

    cond do
      Regex.match?(~r/^[+-]?\d+$/, s) ->
        String.to_integer(String.trim_leading(s, "+"))

      Regex.match?(~r/^0[xX][0-9a-fA-F]+$/, s) ->
        s |> String.slice(2..-1//1) |> String.to_integer(16)

      true ->
        nil
    end
  end

  def bigint(_), do: nil

  @doc "The value a proof authorizes, in the token's smallest unit, or nil."
  def paid_value_of(payment) do
    case dig(payment, ["payload", "authorization", "value"]) do
      v when v in [nil, ""] ->
        nil

      raw ->
        case bigint(raw) do
          v when is_integer(v) and v > 0 -> v
          _ -> nil
        end
    end
  end

  @doc "How many terms `value` buys at `unit` per term: a whole number in [1, max_days], else 0."
  def days_paid(nil, _, _), do: 0

  def days_paid(value, unit, max_days) do
    case bigint(unit) do
      per when is_integer(per) and per > 0 and rem(value, per) == 0 ->
        days = div(value, per)
        if days < 1 or days > max_days, do: 0, else: days

      _ ->
        0
    end
  end

  # ---------------------------------------------------------------- passes --

  defp b64url(bytes), do: Base.url_encode64(bytes, padding: false)
  defp sign(secret, data), do: b64url(:crypto.mac(:hmac, :sha256, secret, data))

  @doc "Mint a pass: `%{token, expires_at, ref}`."
  def mint_pass(secret, ref, expires_at, now \\ System.os_time(:second)) do
    if secret in [nil, ""], do: raise(ArgumentError, "a pass needs a signing secret")
    if expires_at <= now, do: raise(ArgumentError, "a pass needs a future expiry")
    ref_json = if is_nil(ref), do: "null", else: JSON.encode!(ref)
    payload = b64url(~s({"v":1,"iat":#{now},"exp":#{expires_at},"ref":#{ref_json}}))
    %{token: "cp_#{payload}.#{sign(secret, payload)}", expires_at: expires_at, ref: ref}
  end

  @doc "The claims when the signature holds and the pass is live, else nil. Never raises on garbage."
  def read_pass(token, secret, now \\ System.os_time(:second))

  def read_pass("cp_" <> rest, secret, now) when is_binary(secret) and secret != "" do
    with [payload, sig] when payload != "" and sig != "" <- String.split(rest, ".", parts: 2),
         true <- :crypto.hash_equals(sign(secret, payload), sig) || nil,
         {:ok, raw} <- Base.url_decode64(String.trim_trailing(payload, "="), padding: false),
         {:ok, %{"v" => 1, "exp" => exp} = claims} when is_number(exp) <- JSON.decode(raw),
         true <- exp > now do
      %{"exp" => exp, "iat" => claims["iat"], "ref" => claims["ref"]}
    else
      _ -> nil
    end
  rescue
    _ -> nil
  end

  def read_pass(_, _, _), do: nil

  # ------------------------------------------------------------------ edge --

  defp ipv4_to_int(ip) do
    parts = String.split(ip, ".")

    if length(parts) == 4 and Enum.all?(parts, &Regex.match?(~r/^\d{1,3}$/, &1)) do
      ints = Enum.map(parts, &String.to_integer/1)
      if Enum.all?(ints, &(&1 <= 255)), do: Enum.reduce(ints, 0, &(&2 * 256 + &1)), else: nil
    end
  end

  @doc ~S|"a.b.c.d/len" or a bare address -> {base, mask, text}. nil if unreadable.|
  def parse_cidr(cidr) do
    s = String.trim(to_string(cidr))

    {ip, len_raw} =
      case String.split(s, "/", parts: 2) do
        [ip] -> {ip, nil}
        [ip, l] -> {ip, l}
      end

    with base when is_integer(base) <- ipv4_to_int(ip),
         len when is_integer(len) <- parse_len(len_raw) do
      mask = if len == 0, do: 0, else: Bitwise.band(Bitwise.bsl(0xFFFFFFFF, 32 - len), 0xFFFFFFFF)
      {Bitwise.band(base, mask), mask, "#{ip}/#{len}"}
    else
      _ -> nil
    end
  end

  defp parse_len(nil), do: 32

  defp parse_len(l) do
    if Regex.match?(~r/^\d+$/, l) and String.to_integer(l) <= 32,
      do: String.to_integer(l),
      else: nil
  end

  def compile_cidrs(list), do: list |> Enum.map(&parse_cidr/1) |> Enum.reject(&is_nil/1)

  def in_cidrs?(ip, compiled) do
    case ipv4_to_int(String.trim(to_string(ip || ""))) do
      nil -> false
      n -> Enum.any?(compiled, fn {base, mask, _} -> Bitwise.band(n, mask) == base end)
    end
  end

  @doc "The caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop."
  def client_ip(req) do
    real = String.trim(header(req, "x-real-ip") || "")

    cond do
      real != "" ->
        real

      is_nil(header(req, "x-forwarded-for")) ->
        ""

      true ->
        header(req, "x-forwarded-for")
        |> String.split(",")
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))
        |> List.last() || ""
    end
  end

  @doc "Claims Chromium, declares no crawler, sends no Sec-Fetch-Mode: an HTTP client with a copied string."
  def spoofed_browser?(req) do
    ua = header(req, "user-agent") || ""

    Regex.match?(~r{\bChrome/\d+}, ua) and
      not Regex.match?(~r{compatible;|\bbot\b|bot/|crawler|spider|slurp}i, ua) and
      is_nil(header(req, "sec-fetch-mode"))
  end

  @doc "A header of the request map (lower-cased names)."
  def header(%{headers: h}, name), do: Map.get(h, String.downcase(name))

  # ---------------------------------------------------------------- robots --

  @doc "robots.txt with the crawlers sorted the way the gateway sorts them. `sitemap: \"\"` omits it."
  def robots_txt(opts) do
    site_url = Keyword.fetch!(opts, :site_url)
    if site_url in [nil, ""], do: raise(ArgumentError, "robots_txt needs site_url")
    base = String.trim_trailing(site_url, "/")
    disallow = Keyword.get(opts, :disallow, [])
    allow = Keyword.get(opts, :allow, [])
    path = Keyword.get(opts, :path, "/crawl")
    sitemap = Keyword.get(opts, :sitemap, "#{base}/sitemap.xml")
    comments = Keyword.get(opts, :comments, [])

    welcome = fn a ->
      Enum.join(
        ["User-agent: #{a}", "Allow: /"] ++
          Enum.map(allow, &"Allow: #{&1}") ++ Enum.map(disallow, &"Disallow: #{&1}"),
        "\n"
      )
    end

    refuse = fn a -> "User-agent: #{a}\nDisallow: /" end
    charge = fn a -> "#{refuse.(a)}\nAllow: #{path}" end

    lines =
      Enum.map(comments, &"# #{&1}") ++
        if(comments == [], do: [], else: [""]) ++
        Enum.map(Keyword.get(opts, :refused, []), &"#{refuse.(&1)}\n") ++
        Enum.map(Keyword.get(opts, :training, @training), &"#{charge.(&1)}\n") ++
        Enum.map(Keyword.get(opts, :retrieval, @retrieval), &"#{welcome.(&1)}\n") ++
        [welcome.("*"), ""] ++
        if(sitemap == "", do: [], else: ["Sitemap: #{sitemap}", ""])

    Enum.join(lines, "\n")
  end

  # --------------------------------------------------------------- coinpay --

  @doc false
  def httpc_post(url, headers, body) do
    hs = Enum.map(headers, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    case :httpc.request(
           :post,
           {String.to_charlist(url), hs, ~c"application/json", body},
           [timeout: 20_000, connect_timeout: 20_000],
           body_format: :binary
         ) do
      {:ok, {{_, status, _}, _, text}} -> {status, text}
      _ -> {0, ""}
    end
  end

  defp obj(text) do
    case JSON.decode(text) do
      {:ok, m} when is_map(m) -> m
      _ -> %{}
    end
  end

  defp truthy?(v), do: v not in [nil, false, "", 0]

  @doc "Verify, then settle. `%{ok: true, payer, ref}` or `%{ok: false, reason, replay}`."
  def verify_and_settle(payment, expected, api_key, base_url, post) do
    call = fn path, body ->
      {status, text} =
        post.(
          "#{base_url}#{path}",
          [{"content-type", "application/json"}, {"x-api-key", api_key}],
          JSON.encode!(body)
        )

      {status, obj(text)}
    end

    {vs, v} = call.("/api/x402/verify", %{"payment" => payment, "expected" => expected})

    if truthy?(v["valid"]) do
      {ss, s} = call.("/api/x402/settle", %{"payment" => payment})

      if truthy?(s["settled"]) do
        ref =
          case s["txHash"] do
            r when r in [nil, ""] -> nonce_of(payment)
            r -> r
          end

        %{ok: true, payer: dig(v, ["payment", "from"]), ref: ref}
      else
        reason = str(present(s["error"], "settle failed (#{ss})"))

        %{
          ok: false,
          reason: reason,
          replay: Regex.match?(~r/already settled|already being settled/i, reason)
        }
      end
    else
      reason = str(present(v["error"], present(v["reason"], "verify failed (#{vs})")))
      %{ok: false, reason: reason, replay: Regex.match?(~r/already used|replay/i, reason)}
    end
  end

  defp present(nil, default), do: default
  defp present(v, _), do: v

  @doc "Whether the proof has already been paid, when a settle is asked about twice."
  def settle_again(payment, api_key, base_url, post) do
    {_, text} =
      post.(
        "#{base_url}/api/x402/settle",
        [{"content-type", "application/json"}, {"x-api-key", api_key}],
        JSON.encode!(%{"payment" => payment})
      )

    s = obj(text)
    truthy?(s["settled"]) or Regex.match?(~r/already settled/i, str(s["error"]))
  end

  # --------------------------------------------------------------- gateway --

  defstruct [
    :site_url,
    :site_name,
    :coinpay_api_key,
    :coinpay_base_url,
    :pay_to,
    :price_cents,
    :currency,
    :pass_minutes,
    :max_days,
    :header,
    :path,
    :open,
    :denied,
    :charge_spoofed,
    :exempt,
    :training,
    :retrieval,
    :is_paid_agent,
    :secret,
    :page,
    :contact,
    :on_sale,
    :post,
    :now,
    :enabled,
    :buy_url
  ]

  @no_store %{"cache-control" => "no-store", "vary" => "Accept, User-Agent, X-Payment"}

  @doc "Build a gateway. Options carry the reference's names in snake_case; see the README."
  def new(opts) do
    site_url = opts |> Keyword.fetch!(:site_url) |> to_string() |> String.trim_trailing("/")
    if site_url == "", do: raise(ArgumentError, "Gateway needs site_url")
    api_key = to_string(Keyword.get(opts, :coinpay_api_key) || "")
    pay_to = to_string(Keyword.get(opts, :pay_to) || "")
    training = Keyword.get(opts, :training, @training)
    header = String.downcase(to_string(Keyword.get(opts, :header, "x-crawl-pass")))
    path = Keyword.get(opts, :path, "/crawl")
    pass_minutes = Keyword.get(opts, :pass_minutes, 1440)
    max_days = Keyword.get(opts, :max_days, 30)
    secret = to_string(Keyword.get(opts, :secret) || "")

    %__MODULE__{
      site_url: site_url,
      site_name: Keyword.get(opts, :site_name) || URI.parse(site_url).host || site_url,
      coinpay_api_key: api_key,
      coinpay_base_url:
        String.trim_trailing(
          Keyword.get(opts, :coinpay_base_url, "https://coinpayportal.com"),
          "/"
        ),
      pay_to: pay_to,
      price_cents: Keyword.get(opts, :price_cents, 100),
      currency: Keyword.get(opts, :currency, "USD"),
      pass_minutes:
        if(is_integer(pass_minutes) and pass_minutes > 0, do: pass_minutes, else: 1440),
      max_days: if(is_integer(max_days) and max_days >= 1, do: max_days, else: 30),
      header: if(header == "", do: "x-crawl-pass", else: header),
      path: path,
      open:
        ["/robots.txt", path, "/security.txt", "/.well-known/"] ++
          Keyword.get(opts, :open_paths, []),
      denied: compile_cidrs(Keyword.get(opts, :deny_cidrs, [])),
      charge_spoofed: Keyword.get(opts, :charge_spoofed_browsers, false) == true,
      exempt: Keyword.get(opts, :exempt),
      training: training,
      retrieval: Keyword.get(opts, :retrieval, @retrieval),
      is_paid_agent: Keyword.get(opts, :is_paid_agent) || (&training_agent?(&1, training)),
      secret: if(secret == "", do: api_key, else: secret),
      page: Keyword.get(opts, :page) || (&X402Gateway.Page.render/1),
      contact: Keyword.get(opts, :contact, ""),
      on_sale: Keyword.get(opts, :on_sale),
      post: Keyword.get(opts, :post) || (&httpc_post/3),
      now: Keyword.get(opts, :now) || fn -> System.os_time(:second) end,
      enabled: api_key != "" and pay_to != "",
      buy_url: site_url <> path
    }
  end

  def money(g, cents), do: :erlang.float_to_binary(cents / 100, decimals: 2) <> " " <> g.currency
  def price(g), do: money(g, g.price_cents)

  @doc "The offer for `days` terms: the same entries, `days` times the price."
  def offer(g, days \\ 1) do
    if g.enabled do
      extra = if days > 1, do: " (#{days} × #{g.pass_minutes})", else: ""

      build_offer(
        pay_to: g.pay_to,
        price_cents: g.price_cents * days,
        resource: g.buy_url,
        description: "#{days * g.pass_minutes} minutes of crawl access to #{g.site_url}#{extra}"
      )
    else
      %{"x402Version" => 2, "accepts" => []}
    end
  end

  def receipt(g, days \\ 1, extra \\ %{}) do
    g
    |> offer(days)
    |> Map.put("pass", %{
      "price" => price(g),
      "minutes" => g.pass_minutes,
      "days" => days,
      "total" => money(g, g.price_cents * days),
      "maxDays" => g.max_days,
      "header" => g.header,
      "buy" => if(days > 1, do: "#{g.buy_url}?days=#{days}", else: g.buy_url),
      "buyDays" => "#{g.buy_url}?days=<n>"
    })
    |> Map.merge(extra)
  end

  def page_ctx(g, days \\ 1) do
    %{
      days: days,
      total: money(g, g.price_cents * days),
      site_name: g.site_name,
      site_url: g.site_url,
      buy_url: g.buy_url,
      price: price(g),
      minutes: g.pass_minutes,
      max_days: g.max_days,
      header: g.header,
      enabled: g.enabled,
      offer: offer(g),
      training: g.training,
      retrieval: g.retrieval,
      contact: g.contact
    }
  end

  @doc "robots.txt with this gateway's lists and sales path."
  def robots_txt(g, extra) when is_struct(g) do
    robots_txt(
      Keyword.merge(
        [site_url: g.site_url, path: g.path, training: g.training, retrieval: g.retrieval],
        extra
      )
    )
  end

  @doc "The sales page as HTML, for a site that mounts it on a route of its own."
  def page(g), do: g.page.(page_ctx(g))

  @doc "Whether handling this request may call CoinPay (only a proof does)."
  def needs_io?(req), do: not is_nil(header(req, "x-payment"))

  defp resp(status, ct, body, extra \\ %{}) do
    %{
      status: status,
      headers: @no_store |> Map.put("content-type", ct) |> Map.merge(extra),
      body: body
    }
  end

  defp json(body, status, extra \\ %{}),
    do: resp(status, "application/json; charset=utf-8", JSON.encode!(body), extra)

  defp days_from(g, req) do
    case Regex.run(~r/^\s*([+-]?\d+)/, query(req, "days") || "") do
      [_, n] ->
        n = String.to_integer(n)
        if n < 1, do: 1, else: min(n, g.max_days)

      _ ->
        1
    end
  end

  @doc "A query parameter of the request map."
  def query(%{url: url}, name) do
    case URI.parse(url).query do
      nil -> nil
      q -> q |> URI.decode_query() |> Map.get(name)
    end
  end

  def path(%{url: url}) do
    case URI.parse(url).path do
      p when p in [nil, ""] -> "/"
      p -> p
    end
  end

  defp open?(g, p),
    do:
      Enum.any?(g.open, fn o ->
        if String.ends_with?(o, "/"), do: String.starts_with?(p, o), else: p == o
      end)

  defp pass_from(g, req) do
    case header(req, g.header) do
      d when is_binary(d) and d != "" ->
        String.trim(d)

      _ ->
        case Regex.run(
               ~r/^Bearer\s+(cp_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i,
               header(req, "authorization") || ""
             ) do
          [_, t] -> t
          _ -> nil
        end
    end
  end

  defp iso(ts), do: ts |> DateTime.from_unix!() |> Calendar.strftime("%Y-%m-%dT%H:%M:%S.000Z")

  @doc "Answer one request with the sale: a pass as the body of a 200, or a 402 with the offer."
  def sell(g, req) do
    proof = header(req, "x-payment")
    asked = days_from(g, req)

    cond do
      proof not in [nil, ""] ->
        sell_proof(g, req, proof, asked)

      String.contains?(String.downcase(header(req, "accept") || ""), "text/html") ->
        resp(402, "text/html; charset=utf-8", g.page.(page_ctx(g, asked)))

      true ->
        json(
          receipt(g, asked, %{
            "error" => "Payment required for training crawlers. Read #{g.buy_url} for how."
          }),
          402
        )
    end
  end

  defp sell_proof(g, _req, _proof, asked) when not g.enabled,
    do: json(receipt(g, asked, %{"error" => "Payments are not switched on here."}), 402)

  defp sell_proof(g, req, proof, asked) do
    with {:decode, payment} when not is_nil(payment) <- {:decode, decode_payment(proof)},
         {:unit, unit} when not is_nil(unit) <- {:unit, expected_for(payment, offer(g, 1))},
         {:days, days, _} when days > 0 <-
           {:days, days_paid(paid_value_of(payment), unit["amount"], g.max_days), unit} do
      settle(g, req, payment, days, expected_for(payment, offer(g, days)) || unit)
    else
      {:decode, _} ->
        json(receipt(g, asked, %{"error" => "X-PAYMENT is not base64 JSON."}), 402)

      {:unit, _} ->
        json(receipt(g, asked, %{"error" => "Proof does not match an offered network."}), 402)

      {:days, _, unit} ->
        json(
          receipt(g, asked, %{
            "error" =>
              "Pay a whole number of days: #{unit["amount"]} per day in the token's smallest unit, up to #{g.max_days} days. Add ?days=<n> to #{g.buy_url} for the offer."
          }),
          402
        )
    end
  end

  defp settle(g, req, payment, days, expected) do
    term = days * g.pass_minutes * 60
    now = g.now.()
    result = verify_and_settle(payment, expected, g.coinpay_api_key, g.coinpay_base_url, g.post)

    {expires_at, replayed} =
      cond do
        result.ok ->
          {now + term, false}

        result[:replay] ->
          paid = settle_again(payment, g.coinpay_api_key, g.coinpay_base_url, g.post)

          case valid_before_of(payment) do
            vb when paid and is_integer(vb) -> {min(now + term, vb + term), true}
            _ -> {nil, false}
          end

        true ->
          {nil, false}
      end

    if is_nil(expires_at) or expires_at <= now do
      json(
        receipt(g, days, %{"error" => result[:reason] || "Payment could not be settled."}),
        402
      )
    else
      ref = nonce_of(payment) || result[:ref]
      pass = mint_pass(g.secret, ref, expires_at, now)
      expires = iso(pass.expires_at)

      if g.on_sale && !replayed do
        try do
          g.on_sale.(%{
            payer: result[:payer],
            ref: ref,
            token: pass.token,
            expires_at: expires,
            user_agent: header(req, "user-agent") || "",
            price_cents: g.price_cents,
            days: days,
            total_cents: g.price_cents * days,
            currency: g.currency
          })
        rescue
          _ -> :ok
        end
      end

      json(
        %{
          "ok" => true,
          "pass" => pass.token,
          "expires_at" => expires,
          "days" => days,
          "minutes" => days * g.pass_minutes,
          "header" => g.header,
          "replayed" => replayed,
          "use" => ~s(curl -H "#{g.header}: #{pass.token}" #{g.site_url}/)
        },
        200,
        %{g.header => pass.token, "#{g.header}-expires" => expires}
      )
    end
  end

  @doc "The gate. nil means \"not for me, carry on\"."
  def handle(g, req) do
    p = path(req)

    cond do
      g.denied != [] and in_cidrs?(client_ip(req), g.denied) ->
        resp(403, "text/plain; charset=utf-8", "Not available from this network.\n")

      p == g.path ->
        sell(g, req)

      g.exempt && g.exempt.(req) ->
        nil

      not (g.is_paid_agent.(header(req, "user-agent") || "") or
               (g.charge_spoofed and spoofed_browser?(req))) ->
        nil

      open?(g, p) ->
        nil

      true ->
        token = pass_from(g, req)
        if token && read_pass(token, g.secret, g.now.()), do: nil, else: sell(g, req)
    end
  end
end
