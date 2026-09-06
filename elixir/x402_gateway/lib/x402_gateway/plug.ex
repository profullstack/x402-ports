if Code.ensure_loaded?(Plug.Conn) do
  defmodule X402Gateway.Plug do
    @moduledoc """
    The gateway as a Plug: Phoenix, Bandit, Cowboy, anything on Plug.

        # endpoint.ex, before the router
        plug X402Gateway.Plug, gateway: X402Gateway.new(site_url: "https://your-site.com",
                                                        coinpay_api_key: System.get_env("COINPAY_X402_KEY"),
                                                        pay_to: System.get_env("CRAWL_PAY_TO"))

    Or `plug X402Gateway.Plug, site_url: ..., coinpay_api_key: ..., pay_to: ...` to build it in place.
    """
    @behaviour Plug
    import Plug.Conn

    @impl true
    def init(opts) do
      case Keyword.get(opts, :gateway) do
        %X402Gateway{} = g -> g
        nil -> X402Gateway.new(opts)
      end
    end

    @doc "The gateway's request map from a conn."
    def request(conn) do
      headers =
        Enum.reduce(conn.req_headers, %{}, fn {k, v}, acc ->
          Map.update(acc, String.downcase(k), v, &(&1 <> ", " <> v))
        end)

      qs = if conn.query_string == "", do: "", else: "?" <> conn.query_string

      %{
        url: "#{conn.scheme}://#{conn.host}#{port(conn)}#{conn.request_path}#{qs}",
        headers: headers,
        method: conn.method
      }
    end

    defp port(%{scheme: :https, port: 443}), do: ""
    defp port(%{scheme: :http, port: 80}), do: ""
    defp port(%{port: p}), do: ":#{p}"

    @impl true
    def call(conn, gateway) do
      case X402Gateway.handle(gateway, request(conn)) do
        nil ->
          conn

        %{status: status, headers: headers, body: body} ->
          conn
          |> then(&Enum.reduce(headers, &1, fn {k, v}, c -> put_resp_header(c, k, v) end))
          |> send_resp(status, body)
          |> halt()
      end
    end
  end
end
