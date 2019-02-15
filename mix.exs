defmodule APISexAuthMTLS.MixProject do
  use Mix.Project

  def project do
    [
      app: :apisex_auth_mtls,
      version: "0.1.0",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      docs: [
        main: "readme",
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

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.0"},
      {:apisex, github: "tanguilp/apisex", tag: "0.1.0"},
      {:oauth2_utils, github: "tanguilp/oauth2_utils", tag: "master"},
      {:x509, "~> 0.4.0"},
      {:plug_cowboy, "~> 2.0", only: :test},
      {:poison, "~> 3.1", only: :test},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
