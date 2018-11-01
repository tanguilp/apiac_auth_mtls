defmodule APISexAuthMTLS do
  @behaviour Plug
  @behaviour APISex.Authenticator

  @moduledoc """
  Documentation for APISexAuthMTLS.
  """

  @impl Plug
  def init(opts) do
    opts
  end

  @impl Plug
  def call(conn, %{} = opts) do
  end

  @doc """
  `APISex.Authenticator` credential extractor callback

  The returned credentials is a `%X509.Certificate{}` struct
  """
  @impl APISex.Authenticator
  def extract_credentials(conn, _opts) do
    raw_ssl_cert = Plug.Conn.get_peer_data(conn)[:ssl_cert]

    case raw_ssl_cert do
      nil ->
        {:error, conn, :no_client_cert_authentication}

      raw_ssl_cert ->
        case X509.Certificate.from_der(raw_ssl_cert) do
          {:ok, cert} ->
            {:ok, conn, cert}

          {:error, reason} ->
            {:error, conn, reason}
        end
    end
  end

  @doc """
  `APISex.Authenticator` credential validator callback

  The credentials parameter must be an `%X509.Certificate{}` struct
  """
  @impl APISex.Authenticator
  def validate_credentials(conn, %X509.Certificate{} = credentials, opts) do
  end

  @impl APISex.Authenticator
  def set_error_response(conn, _error, opts) do
  end
end
