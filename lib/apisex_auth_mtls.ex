defmodule APISexAuthMTLS do
  @behaviour Plug
  @behaviour APISex.Authenticator

  @moduledoc """
  An `APISex.Authenticator` plug implementing [RFCXXXX](https://tools.ietf.org)
  **section 2** of 'OAuth 2.0 Mutual TLS Client Authentication and Certificate
  Bound Access Tokens'

  Using this scheme, authentication is performed thanks to 2 elements:
  - TLS client certificate authentication
  - the `client_id` paramter of the `application/x-www-form-urlencoded` body

  TLS client certificate authentication may be performed using two methods:
  - a certificate issued by a Certificate Authority (CA) which is called [PKI
  Mutual TLS OAuth Client Authentication Method](https://tools.ietf.org/html/draft-ietf-oauth-mtls-12#section-2.1).
  In this case, the certificate **Distinguished Name** (DN) is checked against
  the DN registered for the `client_id`
  - a self-signed, self-issued certificate which is called [Self-Signed Certificate
  Mutual TLS OAuth Client Authentication Method](https://tools.ietf.org/html/draft-ietf-oauth-mtls-12#section-2.2).
  In this case, the certificate is checked against the **subject public key info**
  of the registered certificates of the `client_id`

  ## Plug options

  - `allowed_methods`: one of `:pki`, `:selfsigned` or `:both`. No default value,
  mandatory option
  - `pki_callback`: a `(String.t -> String.t | nil)` function that takes the `client_id` as
  a parameter and returns its DN as a `String.t` or `nil` if no DN is registered for
  that client
  - `selfsigned_callback`: a `(String.t -> binary() | [binary()] | nil)`
  function that takes the `client_id` as a parameter and returns the DER-encoded certificate
  or the list of DER-encoded certificate for `the client_id`, or `nil` if no certificate
  is registered for that client
  - `set_authn_error_response`: if `true`, sets the HTTP status code to `401`.
  If false, does not change them. Defaults to `true`
  - `halt_on_authn_failure`: if set to `true`, halts the connection and directly sends the
  response. When set to `false`, does nothing and therefore allows chaining several
  authenticators. Defaults to `true`

  ## Example

  ## Configuring Phoenix for `#{inspect(__MODULE__)}` authentication

  ## Security considerations

  ## Other considerations

  When activating TLS client authentication, be aware that some browser user
  interfaces may prompt the user, in a unpredictable manner, for certificate
  selection. You may want to consider starting a TLS-authentication-enabled
  endpoint on another port (i.e. one port for web browsing, another one for
  API access).

  """

  @impl Plug
  def init(opts) do
    if is_nil(opts[:allowed_methods]), do: raise ":allowed_methods mandatory option no set"

    case {opts[:allowed_methods], opts[:pki_callback], opts[:selfsigned_callback]} do
      {method, pki_callback, _} when method in [:pki, :both] and not is_function(pki_callback, 1) ->
        raise "Missing :pki_callback option"

      {method, _, selfsigned_callback} when method in [:selfsigned, :both] and not is_function(selfsigned_callback, 1) ->
        raise "Missing :selfsigned_callback option"

      _ ->
        :ok
    end

    %{opts |
      set_authn_error_response: Keyword.get(opts, :set_authn_error_response, true),
      halt_on_authn_failure: Keyword.get(opts, :halt_on_authn_failure, true)
    }
  end

  @impl Plug
  def call(conn, opts) do
    with {:ok, conn, credentials} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, credentials, opts)
    do
      conn
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{} = error} ->
        conn =
          if opts[:set_authn_error_response] do
            set_error_response(conn, error, opts)
          else
            conn
          end

        if opts[:halt_on_authn_failure] do
          conn
          |> Plug.Conn.send_resp()
          |> Plug.Conn.halt()
        else
          conn
        end
    end
  end

  @doc """
  `APISex.Authenticator` credential extractor callback

  The returned credentials is a `{String.t, binary}` tuple where:
  - the first parameter is the `client_id`
  - the second parameter is the raw DER-encoded certificate
  """
  @impl APISex.Authenticator
  def extract_credentials(conn, _opts) do
    with {:ok, conn, client_id} <- get_client_id(conn),
         {:ok, ssl_cert} <- get_peer_cert(conn)
    do
      {:ok, conn, {client_id, ssl_cert}}
    else
      {:error, conn, reason} ->
        {:error, conn, %APISex.Authenticator.Unauthorized{
          authenticator: __MODULE__,
          reason: reason}}
    end
  end

  defp get_client_id(conn) do
    try do
      plug_parser_opts = Plug.Parsers.init(parsers: [:urlencoded],
                                           pass: ["application/x-www-form-urlencoded"])

      conn = Plug.Parsers.call(conn, plug_parser_opts)

      client_id = conn.body_params["client_id"]

      if client_id != nil and OAuth2Utils.client_id?(client_id) do
        {:ok, conn, client_id}
      else
        {:error, conn, :client_id_not_found_or_invalid}
      end
    rescue
      UnsupportedMediaTypeError ->
        {:error, conn, :unsupported_media_type}
    end
  end

  defp get_peer_cert(conn) do
    raw_tls_cert = Plug.Conn.get_peer_data(conn)[:ssl_cert]

    case raw_tls_cert do
      nil ->
        {:error, conn, :no_client_cert_authentication}

      raw_tls_cert ->
        {:ok, conn, raw_tls_cert}
    end
  end

  @doc """
  `APISex.Authenticator` credential validator callback

  The credentials parameter must be an `%X509.Certificate{}` struct
  """
  @impl APISex.Authenticator
  def validate_credentials(conn, {client_id, raw_tls_cert}, opts) do
    # not documented, but pkix_decode_cert/2 returns an {:error, reason} tuple
    case X509.Certificate.from_der(raw_tls_cert, :otp) do
      {:error, _} ->
        {:error, conn, :cert_decode_error}

      cert ->
        # technically a root CA certificate is also self-signed, however it
        # 1- is absolutely unlikely it would be used for that
        # 2- wouldn't have the same public key info, so couldn't impersonate
        # another client
        # TODO: confirm these assumptions
        if :public_key.pkix_is_self_signed(cert)
          and opts[:allowed_methods] in [:selfsigned, :both] do
          validate_self_signed_cert(conn, client_id, cert, opts)
        else
          if opts[:allowed_methods] in [:pki, :both] do
            validate_pki_cert(conn, client_id, cert, opts)
          else
            {:error, conn, %APISex.Authenticator.Unauthorized{
              authenticator: __MODULE__,
              reason: :no_method_provided}}
          end
        end
    end
  end

  defp validate_self_signed_cert(conn, client_id, cert, opts) do
    # TODO: could we not use X509 package to reduce attack surface?
    # looks like decoding cert info requires additional Erlang code:
    # https://github.com/jshmrtn/phoenix-client-ssl/blob/master/lib/public_key_subject.erl

    peer_cert_subject_public_key_info = get_subject_public_key_info(cert)

    registered_certs = opts[:selfsigned_callback].(client_id)

    public_key_info_match = Enum.any?(
      if is_list(registered_certs) do
        registered_certs
      else
        [registered_certs] # when only one cert is returned
      end,
      fn registered_cert ->
        # TODO: is that ok to compare nested struct like this?
        # should we pattern match with = instead?
        get_subject_public_key_info(registered_cert) == peer_cert_subject_public_key_info
      end
    )

    if public_key_info_match do
      conn =
        conn
        |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apisex_client, client_id)

      {:ok, conn}
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{
              authenticator: __MODULE__,
              reason: :selfsigned_no_cert_match}}
    end
  end

  # destructuring cert, documentation:
  # http://erlang.org/documentation/doc-6.2/lib/public_key-0.22.1/doc/html/cert_records.html
  defp get_subject_public_key_info({:OTPCertificate, tbsCertificate, _signatureAlgorithm, _signature}) do
    {:OTPTBSCertificate,
      _version,
      _serialNumber,
      _signature,
      _issuer,
      _validity,
      _subject,
      subjectPublicKeyInfo,
      _issuerUniqueID,
      _subjectUniqueID,
      _extensions
    } = tbsCertificate

    subjectPublicKeyInfo
  end

  defp get_subject_public_key_info(der_encoded_cert) do
    X509.Certificate.from_der(der_encoded_cert, :otp)
    |> get_subject_public_key_info()
  end

  defp validate_pki_cert(conn, client_id, cert, opts) do
    registered_client_cert_sdn_str = opts[:pki_callback].(client_id)

    peer_cert_sdn_str =
      cert
      |> X509.Certificate.subject()
      |> X509.RDNSequence.to_string()

      # TODO: is comparing string representations of this DNs ok on a security
      # point of view? Or shall we compare the raw SDNs?
      # See further https://tools.ietf.org/html/rfc5280#section-7.1
    if registered_client_cert_sdn_str == peer_cert_sdn_str do
      conn =
        conn
        |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apisex_client, client_id)

      {:ok, conn}
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{
              authenticator: __MODULE__,
              reason: :pki_no_dn_match}}
    end
  end

  @impl APISex.Authenticator
  def set_error_response(conn, _error, _opts) do
    conn
    |> Plug.Conn.resp(:unauthorized, "")
  end
end
