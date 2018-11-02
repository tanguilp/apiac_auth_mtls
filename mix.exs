defmodule APISexAuthMTLS.MixProject do
  use Mix.Project

  def project do
    [
      app: :apisex_auth_mtls,
      version: "0.1.0",
      elixir: "~> 1.7",
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
      {:plug, "~> 1.0"},
      {:apisex, github: "tanguilp/apisex", tag: "master"},
      {:oauth2_utils, github: "tanguilp/oauth2_utils", tag: "master"},
      {:x509, "~> 0.4.0"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
