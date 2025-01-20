defmodule ICPAgent.MixProject do
  use Mix.Project

  @url "https://github.com/diodechain/icp_agent"
  def project do
    [
      app: :icp_agent,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),

      # Hex
      description: "ICPAgent is an Elixir agent for the Internet Computer (ICP).",
      package: [
        licenses: ["Apache-2.0"],
        maintainers: ["Dominic Letz"],
        links: %{"GitHub" => @url}
      ],
      # Docs
      name: "Candid",
      source_url: @url,
      docs: [
        # The main page in the docs
        main: "Candid",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp aliases do
    [
      lint: ["format --check-formatted", "credo --strict", "dialyzer"]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:candid, "~> 1.0"},
      {:cbor, "~> 1.0"},
      {:diode_client, "~> 1.0"},
      {:ex_sha3, "~> 0.1.1"},
      {:jason, "~> 1.4"},
      {:req, "~> 0.5.8"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.25.0", only: :dev}
    ]
  end
end
