defmodule APIacAuthMTLS.MixProject do
  use Mix.Project

  def project do
    [
      app: :apiac_auth_mtls,
      description: "APIac Elixir plug for mutual TLS authentication (RFC8705)",
      version: "1.0.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      package: package(),
      source_url: "https://github.com/tanguilp/apiac_auth_mtls"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.0"},
      {:apiac, "~> 1.0"},
      {:oauth2_utils, "~> 0.1.0"},
      {:x509, "~> 0.8.0"},
      {:plug_cowboy, "~> 2.0", only: :test},
      {:poison, "~> 4.0", only: :test},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/apiac_auth_mtls"}
    ]
  end
end
