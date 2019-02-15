defmodule APISexAuthMTLS do
  @behaviour Plug
  @behaviour APISex.Authenticator

  @moduledoc """
  An `APISex.Authenticator` plug implementing
  [RFCXXXX](https://tools.ietf.org/html/draft-ietf-oauth-mtls-12)
  **section 2** of 'OAuth 2.0 Mutual TLS Client Authentication and Certificate
  Bound Access Tokens'

  Using this scheme, authentication is performed thanks to 2 elements:
  - TLS client certificate authentication
  - the `client_id` parameter of the `application/x-www-form-urlencoded` body

  TLS client certificate authentication may be performed thanks to two methods:
  - authentication with
  a certificate issued by a Certificate Authority (CA) which is called [PKI
  Mutual TLS OAuth Client Authentication Method](https://tools.ietf.org/html/draft-ietf-oauth-mtls-12#section-2.1).
  In this case, the certificate **Distinguished Name** (DN) is checked against
  the DN registered for the `client_id`
  - authentication with a self-signed, self-issued certificate which is called [Self-Signed Certificate
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
  function that takes the `client_id` as a parameter and returns the certificate
  or the list of the certificate for `the client_id`, or `nil` if no certificate
  is registered for that client. Certificates can be returned in DER-encoded format, or
  native OTP certificate structure
  - `set_error_response`: function called when authentication failed. Defaults to
  `APISexAuthBasic.send_error_response/3`
  - `error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
  Defaults to `:normal`

  ## Example

  ```elixir
  plug APISexAuthBasic, allowed_methods: :both,
                        selfsigned_callback: &selfsigned_certs/1,
                        pki_callback: &get_dn/1

  # further

  defp selfsigned_certs(client_id) do
    :ets.lookup_element(:clients, :client_id, 5)
  end

  defp get_dn("client-1") do
    "/C=US/ST=ARI/L=Chicago/O=Agora/CN=API access certificate"
  end

  defp get_dn(_), do: nil
  ```

  ## Configuring TLS for `#{inspect(__MODULE__)}` authentication

  Plugs can authenticate requests on elements contained in the HTTP request.
  Mutual TLS authentication, however, occurs on the TLS layer and the authentication
  context is only then passed to the plug (`peer_data`).

  Usually, when using TLS, only the server is authenticated by the client. But client
  authentication by the server can also be activated on an TLS-enabled server:
  in this case, both the server and the clients authenticate to each other.
  Client authentication can either be optional or mandatory.

  When a TLS-enabled server authenticates a client, it checks the client's certificate
  against its list of known certificate authorities (CA). CAs are trusted root certificates.
  The list of CAs can be changed through configuration.

  Note that by default, the Erlang TLS stack does not accept self-signed certificate.
  FIXME: what is the rationale?

  All TLS options are documented in the
  [Erlang SSL module documentation](http://erlang.org/doc/man/ssl.html).

  ### Enabling TLS client authentication

  This table summarizes which options are to be activated *on the server*:

  | Use-case                            | TLS options                                             |
  |-------------------------------------|---------------------------------------------------------|
  | No client authentication (default)  | (no specific option to set)                             |
  | Optional client authentication      | -`verify: :verify_peer`                                 |
  | Mandatory client authentication     | -`verify: :verify_peer`<br>- `fail_if_no_peer_cert: true` |

  ### Example with `plug_cowboy`

  To enable optional TLS client authentication:
  ```elixir
  Plug.Cowboy.https(MyPlug, [],
                    port: 8443,
                    keyfile: "priv/ssl/key.pem",
                    certfile: "priv/ssl/cer.pem",
                    verify: :verify_peer)
  ```

  To enable mandatory TLS client authentication:
  ```elixir
  Plug.Cowboy.https(MyPlug, [],
                    port: 8443,
                    keyfile: "priv/ssl/key.pem",
                    certfile: "priv/ssl/cer.pem",
                    verify: :verify_peer,
                    fail_if_no_peer_cert: true)
  ```

  ### Allowing TLS connection of clients with self-signed certificates

  By default, Erlang's TLS stack rejects self-signed client certificates. To allow it,
  use the `verify_fun` TLS parameter with the following function:

  ```elixir
  defp verify_fun_selfsigned_cert(_, {:bad_cert, :selfsigned_peer}, user_state),
    do: {:valid, user_state}

  defp verify_fun_selfsigned_cert(_, {:bad_cert, _} = reason, _),
    do: {:fail, reason}

  defp verify_fun_selfsigned_cert(_, {:extension, _}, user_state),
    do: {:unkown, user_state}

  defp verify_fun_selfsigned_cert(_, :valid, user_state),
    do: {:valid, user_state}

  defp verify_fun_selfsigned_cert(_, :valid_peer, user_state),
    do: {:valid, user_state}
  ```

  Example with `plug_cowboy`:

  ```elixir
  Plug.Cowboy.https(MyPlug, [],
                    port: 8443,
                    keyfile: "priv/ssl/key.pem",
                    certfile: "priv/ssl/cer.pem",
                    verify: :verify_peer,
                    verify_fun: {&verify_fun_selfsigned_cert/3, []})
  ```

  FIXME: what are the security implications of doing that?

  ## Security considerations

  In addition to the security considerations listed in the RFC, consider that:
  - Before TLS1.3, client authentication may leak information
  ([further information](https://blog.funkthat.com/2018/10/tls-client-authentication-leaks-user.html))
  - Any CA can signe for any DN (as for any other certificate attribute). Though this is
  a well-known security limitation of the X509 infrastructure, issuing certificate with
  rogue DNs may be more difficult to detect (because less monitored)

  ## Other considerations

  When activating TLS client authentication, be aware that some browser user
  interfaces may prompt the user, in a unpredictable manner, for certificate
  selection. You may want to consider starting a TLS-authentication-enabled
  endpoint on another port (i.e. one port for web browsing, another one for
  API access).

  """

  @impl Plug
  def init(opts) do
    if is_nil(opts[:allowed_methods]), do: raise(":allowed_methods mandatory option not set")

    case {opts[:allowed_methods], opts[:pki_callback], opts[:selfsigned_callback]} do
      {method, pki_callback, _}
      when method in [:pki, :both] and not is_function(pki_callback, 1) ->
        raise "Missing :pki_callback option"

      {method, _, selfsigned_callback}
      when method in [:selfsigned, :both] and not is_function(selfsigned_callback, 1) ->
        raise "Missing :selfsigned_callback option"

      _ ->
        :ok
    end

    opts
    |> Enum.into(%{})
    |> Map.put_new(:set_error_response, &APISexAuthMTLS.send_error_response/3)
    |> Map.put_new(:error_response_verbosity, :normal)
  end

  @impl Plug
  @spec call(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()
  def call(conn, %{} = opts) do
    if APISex.authenticated?(conn) do
      conn
    else
      do_call(conn, opts)
    end
  end

  def do_call(conn, opts) do
    with {:ok, conn, credentials} <- extract_credentials(conn, opts),
         {:ok, conn} <- validate_credentials(conn, credentials, opts) do
      conn
    else
      {:error, conn, %APISex.Authenticator.Unauthorized{} = error} ->
        opts[:set_error_response].(conn, error, opts)
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
         {:ok, ssl_cert} <- get_peer_cert(conn) do
      {:ok, conn, {client_id, ssl_cert}}
    else
      {:error, conn, reason} ->
        {:error, conn,
         %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: reason}}
    end
  end

  defp get_client_id(conn) do
    try do
      plug_parser_opts =
        Plug.Parsers.init(
          parsers: [:urlencoded],
          pass: ["application/x-www-form-urlencoded"]
        )

      conn = Plug.Parsers.call(conn, plug_parser_opts)

      client_id = conn.body_params["client_id"]

      if client_id != nil and OAuth2Utils.valid_client_id_param?(client_id) do
        {:ok, conn, client_id}
      else
        {:error, conn, :credentials_not_found}
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
        {:ok, raw_tls_cert}
    end
  end

  @doc """
  `APISex.Authenticator` credential validator callback

  The credentials parameter must be an `%X509.Certificate{}` struct
  """
  @impl APISex.Authenticator
  def validate_credentials(conn, {client_id, raw_tls_cert}, opts) do
    # not documented, but pkix_decode_cert/2 returns an {:error, reason} tuple
    case X509.Certificate.from_der(raw_tls_cert) do
      {:error, _} ->
        {:error, conn, :cert_decode_error}

      {:ok, cert} ->
        # technically a root CA certificate is also self-signed, however it
        # 1- is absolutely unlikely it would be used for that
        # 2- wouldn't have the same public key info, so couldn't impersonate
        # another client
        # TODO: confirm these assumptions
        if :public_key.pkix_is_self_signed(cert) and
             opts[:allowed_methods] in [:selfsigned, :both] do
          validate_self_signed_cert(conn, client_id, cert, opts)
        else
          if opts[:allowed_methods] in [:pki, :both] do
            validate_pki_cert(conn, client_id, cert, opts)
          else
            {:error, conn,
             %APISex.Authenticator.Unauthorized{
               authenticator: __MODULE__,
               reason: :no_method_provided
             }}
          end
        end
    end
  end

  defp validate_self_signed_cert(conn, client_id, cert, opts) do
    # TODO: could we not use X509 package to reduce vuln surface?
    # looks like decoding cert info requires additional Erlang code:
    # https://github.com/jshmrtn/phoenix-client-ssl/blob/master/lib/public_key_subject.erl

    peer_cert_subject_public_key_info = get_subject_public_key_info(cert)
    IO.inspect(peer_cert_subject_public_key_info)

    registered_certs = opts[:selfsigned_callback].(client_id)

    public_key_info_match =
      Enum.any?(
        if is_list(registered_certs) do
          registered_certs
        else
          # when only one cert is returned, or nil was returned
          [registered_certs]
        end,
        fn registered_cert ->
          # FIXME: is that ok to compare nested struct like this?
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
      {:error, conn,
       %APISex.Authenticator.Unauthorized{
         authenticator: __MODULE__,
         reason: :selfsigned_no_cert_match
       }}
    end
  end

  # destructuring cert, documentation:
  # http://erlang.org/documentation/doc-6.2/lib/public_key-0.22.1/doc/html/cert_records.html
  defp get_subject_public_key_info(
         {:OTPCertificate, tbsCertificate, _signatureAlgorithm, _signature}
       ) do
    {:OTPTBSCertificate, _version, _serialNumber, _signature, _issuer, _validity, _subject,
     subjectPublicKeyInfo, _issuerUniqueID, _subjectUniqueID, _extensions} = tbsCertificate

    subjectPublicKeyInfo
  end

  defp get_subject_public_key_info(der_encoded_cert) do
    X509.Certificate.from_der!(der_encoded_cert)
    |> get_subject_public_key_info()
  end

  defp validate_pki_cert(conn, client_id, cert, opts) do
    registered_client_cert_sdn_str = opts[:pki_callback].(client_id)

    peer_cert_sdn_str =
      cert
      |> X509.Certificate.subject()
      |> X509.RDNSequence.to_string()

    # FIXME: is comparing string representations of this DNs ok on a security
    # point of view? Or shall we compare the raw SDNs?
    # See further https://tools.ietf.org/html/rfc5280#section-7.1
    # FIXME: registered_client_cert can be `nil` Can a certificate's DN
    # be `nil` too?
    if registered_client_cert_sdn_str == peer_cert_sdn_str do
      conn =
        conn
        |> Plug.Conn.put_private(:apisex_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apisex_client, client_id)

      {:ok, conn}
    else
      {:error, conn,
       %APISex.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :pki_no_dn_match}}
    end
  end

  @doc """
  Implementation of the `APISex.Authenticator` callback

  ## Verbosity

  The following elements in the HTTP response are set depending on the value
  of the `:error_response_verbosity` option:

  | Error response verbosity  | HTTP Status        | Headers | Body                                                    |
  |:-------------------------:|--------------------|---------|---------------------------------------------------------|
  | `:debug`                  | Unauthorized (401) |         | `APISex.Authenticator.Unauthorized` exception's message |
  | `:normal`                 | Unauthorized (401) |         |                                                         |
  | `:minimal`                | Unauthorized (401) |         |                                                         |

  """
  @impl APISex.Authenticator
  def send_error_response(conn, _error, %{:error_response_verbosity => error_response_verbosity})
      when error_response_verbosity in [:normal, :minimal] do
    conn
    |> Plug.Conn.send_resp(:unauthorized, "")
    |> Plug.Conn.halt()
  end

  def send_error_response(conn, error, %{:error_response_verbosity => :debug}) do
    conn
    |> Plug.Conn.send_resp(:unauthorized, Exception.message(error))
    |> Plug.Conn.halt()
  end

  @doc """
  Saves failure in a `Plug.Conn.t()`'s private field and returns the `conn`

  See the `APISex.AuthFailureResponseData` module for more information.
  """
  @spec save_authentication_failure_response(Plug.Conn.t(),
                                             %APISex.Authenticator.Unauthorized{},
                                             any()) :: Plug.Conn.t()
  def save_authentication_failure_response(conn, error, opts) do
    failure_response_data =
      %APISex.AuthFailureResponseData{
        module: __MODULE__,
        reason: error.reason,
        www_authenticate_header: nil,
        status_code: :unauthorized,
        body:
          if opts[:error_response_verbosity] in [:normal, :minimal] do
            nil
          else
            Exception.message(error)
          end
      }

    APISex.AuthFailureResponseData.put(conn, failure_response_data)
  end
end
