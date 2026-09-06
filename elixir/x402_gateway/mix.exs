defmodule X402Gateway.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source "https://github.com/profullstack/x402-ports"

  def project do
    [
      app: :x402_gateway,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Sell crawl access to AI training crawlers by the day over x402, settled by CoinPay. A Plug: 402 with an offer, a sales page, signed passes, robots.txt. A port of @profullstack/x402-gateway.",
      package: [
        licenses: ["MIT"],
        links: %{
          "GitHub" => @source,
          "Reference" => "https://github.com/profullstack/x402-gateway"
        },
        files: ~w(lib mix.exs README.md)
      ],
      docs: [main: "readme", extras: ["README.md"]],
      source_url: @source
    ]
  end

  def application, do: [extra_applications: [:logger, :inets, :ssl, :crypto]]

  defp deps do
    [
      {:plug, "~> 1.14", optional: true}
    ]
  end
end
