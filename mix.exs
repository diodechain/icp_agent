defmodule ICPAgent.MixProject do
  use Mix.Project

  def project do
    [
      app: :icp_agent,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:candid, "~> 1.0"},
      {:diode_client, "~> 1.0"},
      {:cbor, "~> 1.0"},
      {:jason, "~> 1.4"},
      {:ex_sha3, "~> 0.1.1"},
      {:req, "~> 0.5.8"}
    ]
  end
end
