defmodule X402Gateway.VectorsTest do
  use ExUnit.Case, async: true

  @v (System.get_env("X402_VECTORS") || Path.expand("../../../spec/vectors.json", __DIR__))
     |> File.read!()
     |> JSON.decode!()
  @c @v["constants"]
  @now @c["NOW"]
  @site @c["SITE"]

  defp gateway(extra \\ []) do
    g = @v["gateway"]
    sub = g["exempt"]

    X402Gateway.new(
      Keyword.merge(
        [
          site_url: g["siteUrl"],
          coinpay_api_key: g["coinpay"]["apiKey"],
          pay_to: g["payTo"],
          deny_cidrs: g["denyCidrs"],
          charge_spoofed_browsers: g["chargeSpoofedBrowsers"],
          open_paths: g["openPaths"],
          exempt: fn r -> String.contains?(X402Gateway.header(r, "cookie") || "", sub) end,
          now: fn -> @now end,
          post: fn url, _, _ -> raise "CoinPay must not be called: #{url}" end
        ],
        extra
      )
    )
  end

  defp req(c),
    do: %{
      url: @site <> c["url"],
      headers: Map.new(c["headers"], fn {k, v} -> {String.downcase(k), v} end),
      method: "GET"
    }

  test "passes" do
    for p <- @v["passes"] do
      assert X402Gateway.mint_pass(p["secret"], p["ref"], p["exp"], p["iat"]).token == p["token"]
    end

    for c <- @v["readPass"] do
      r = X402Gateway.read_pass(c["token"], c["secret"] || @c["SECRET"], c["now"])
      assert r != nil == c["ok"], inspect(c)
      if c["ok"], do: assert(r == c["claims"])
    end
  end

  test "offers, payments, days" do
    for o <- @v["offers"] do
      i = o["in"]

      opts = [
        pay_to: i["payTo"],
        price_cents: i["priceCents"],
        resource: i["resource"],
        description: i["description"]
      ]

      opts =
        if i["maxTimeoutSeconds"],
          do: Keyword.put(opts, :max_timeout_seconds, i["maxTimeoutSeconds"]),
          else: opts

      assert X402Gateway.build_offer(opts) == o["out"]
    end

    offer = hd(@v["offers"])["out"]

    for p <- @v["payments"] do
      d = X402Gateway.decode_payment(p["header"])
      assert d != nil == p["decodes"], inspect(p)

      if Map.has_key?(p, "expected"),
        do: assert(X402Gateway.expected_for(d, offer) == p["expected"], inspect(p))
    end

    for d <- @v["daysPaid"] do
      v = if d["value"], do: X402Gateway.bigint(d["value"]), else: nil
      v = if is_integer(v) and v <= 0, do: nil, else: v
      assert X402Gateway.days_paid(v, d["unit"], d["maxDays"]) == d["days"], inspect(d)
    end
  end

  test "agents, edge, robots" do
    for a <- @v["agents"],
        do: assert(X402Gateway.training_agent?(a["ua"]) == a["training"], a["ua"])

    c = X402Gateway.compile_cidrs(@v["cidrs"]["list"])
    assert Enum.map(c, &elem(&1, 2)) == @v["cidrs"]["compiled"]

    for k <- @v["cidrs"]["cases"],
        do: assert(X402Gateway.in_cidrs?(k["ip"], c) == k["hit"], k["ip"])

    n = X402Gateway.compile_cidrs(@v["cidrs"]["narrow"]["list"])

    for k <- @v["cidrs"]["narrow"]["cases"],
        do: assert(X402Gateway.in_cidrs?(k["ip"], n) == k["hit"], k["ip"])

    for k <- @v["clientIp"],
        do:
          assert(
            X402Gateway.client_ip(%{url: @site <> "/", headers: k["headers"]}) == k["ip"],
            inspect(k)
          )

    for s <- @v["spoofs"] do
      assert X402Gateway.spoofed_browser?(%{
               url: @site <> "/",
               headers: Map.put(s["headers"], "user-agent", s["ua"])
             }) == s["spoofed"],
             s["ua"]
    end

    for r <- @v["robots"] do
      i = r["in"]
      opts = [site_url: i["siteUrl"]]

      opts =
        Enum.reduce(
          ~w(disallow allow sitemap path refused training retrieval comments),
          opts,
          fn k, acc ->
            if Map.has_key?(i, k), do: Keyword.put(acc, String.to_atom(k), i[k]), else: acc
          end
        )

      assert X402Gateway.robots_txt(opts) == r["out"]
    end
  end

  defp check(gw, c) do
    r = X402Gateway.handle(gw, req(c))

    if c["pass"] do
      assert r == nil, c["name"]
    else
      assert r != nil, c["name"]
      assert r.status == c["status"], c["name"]

      if c["contentType"],
        do:
          assert(hd(String.split(r.headers["content-type"], ";")) == c["contentType"], c["name"])

      if Map.has_key?(c, "body"), do: assert(JSON.decode!(r.body) == c["body"], c["name"])
      if c["text"], do: assert(r.body == c["text"], c["name"])

      for s <- c["htmlContains"] || [],
          do: assert(String.contains?(r.body, s), "#{c["name"]}: #{s}")

      for {k, v} <- c["responseHeaders"] || %{},
          do: assert(r.headers[k] == v, "#{c["name"]}: #{k}")
    end
  end

  test "handle" do
    gw = gateway()
    for c <- @v["handle"], do: check(gw, c)
    d = X402Gateway.new(site_url: @site, now: fn -> @now end)
    for c <- @v["disabled"], do: check(d, c)
    assert X402Gateway.robots_txt(gw, []) == X402Gateway.robots_txt(site_url: @site)
    assert String.contains?(X402Gateway.page(gw), "1.00 USD")
  end

  test "plug" do
    conn =
      Plug.Test.conn(:get, "https://example.com/some?x=1")
      |> Plug.Conn.put_req_header("user-agent", "GPTBot")

    conn = X402Gateway.Plug.call(conn, X402Gateway.Plug.init(gateway: gateway()))
    assert conn.status == 402
    assert conn.halted
    assert JSON.decode!(conn.resp_body)["x402Version"] == 2

    human =
      Plug.Test.conn(:get, "https://example.com/")
      |> Plug.Conn.put_req_header("user-agent", "curl/8")

    refute X402Gateway.Plug.call(human, X402Gateway.Plug.init(gateway: gateway())).halted
  end

  test "paid" do
    for c <- @v["coinpay"]["paid"] do
      {:ok, calls} = Agent.start_link(fn -> [] end)
      {:ok, sales} = Agent.start_link(fn -> 0 end)

      post = fn url, headers, body ->
        assert List.keyfind(headers, "x-api-key", 0) == {"x-api-key", @c["SECRET"]}
        Agent.update(calls, &(&1 ++ [{url, JSON.decode!(body)}]))

        settles =
          calls
          |> Agent.get(& &1)
          |> Enum.count(fn {u, _} -> String.ends_with?(u, "/api/x402/settle") end)

        out =
          cond do
            String.ends_with?(url, "/api/x402/verify") -> c["verify"]
            settles == 1 and c["settle"] -> c["settle"]
            true -> c["settleAgain"] || c["settle"] || %{}
          end

        {200, JSON.encode!(out)}
      end

      gw = gateway(post: post, on_sale: fn _ -> Agent.update(sales, &(&1 + 1)) end)
      proof = Base.encode64(JSON.encode!(c["proof"]))

      r =
        X402Gateway.handle(gw, %{
          url: @site <> "/crawl",
          headers: %{"x-payment" => proof, "user-agent" => "curl/8"},
          method: "GET"
        })

      assert r.status == c["status"], "#{c["name"]}: #{r.body}"
      body = JSON.decode!(r.body)

      if c["status"] == 200 do
        assert body["ok"]
        assert body["days"] == c["days"], c["name"]
        if c["minutes"], do: assert(body["minutes"] == c["minutes"])
        assert body["replayed"] == c["replayed"], c["name"]
        claims = X402Gateway.read_pass(body["pass"], @c["SECRET"], @now)
        assert claims
        if c["ref"], do: assert(claims["ref"] == c["ref"], c["name"])
        if c["expiresAt"], do: assert(claims["exp"] == c["expiresAt"], c["name"])
        assert r.headers["x-crawl-pass"] == body["pass"]
        assert Agent.get(sales, & &1) == if(c["replayed"], do: 0, else: 1), c["name"]
        [{_, verify} | _] = Agent.get(calls, & &1)
        assert verify["expected"]["amount"] == Integer.to_string(1_000_000 * c["days"])
      else
        if c["error"], do: assert(body["error"] == c["error"], c["name"])
        assert Agent.get(sales, & &1) == 0
      end
    end
  end
end
