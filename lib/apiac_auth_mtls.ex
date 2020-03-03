defmodule APIacAuthMTLS do
  @behaviour Plug
  @behaviour APIac.Authenticator

  @moduledoc """

  An `APIac.Authenticator` plug implementing **section 2** of
  OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
  ([RFC8705](https://tools.ietf.org/html/rfc8705))

  Using this scheme, authentication is performed thanks to 2 elements:
  - TLS client certificate authentication
  - the `client_id` parameter of the `application/x-www-form-urlencoded` body

  TLS client certificate authentication may be performed thanks to two methods:
  - authentication with a certificate issued by a Certificate Authority (CA) which is called
  [PKI Mutual-TLS Method](https://tools.ietf.org/html/rfc8705#section-2.1).
  In this case, one of the following certificate attribute is checked against
  this attribute registered for the `client_id`:
    - Distinguished name
    - SAN DNS
    - SAN URI
    - SAN IP address
    - SAN email
  - authentication with a self-signed, self-issued certificate which is called
  [Self-Signed Certificate Mutual-TLS Method](https://tools.ietf.org/html/rfc8705#section-2.2).
  In this case, the certificate is checked against the **subject public key info**
  of the registered certificates of the `client_id`

  ## Plug options

  - `:allowed_methods`: one of `:pki`, `:selfsigned` or `:both`. No default value,
  mandatory option
  - `:pki_callback`: a
  `(String.t -> String.t | {tls_client_auth_subject_value(), String.t()} | nil)`
  function that takes the `client_id` as a parameter and returns its DN as a `String.t()` or
  `{tls_client_auth_subject_value(), String.t()}` or `nil` if no DN is registered for
  that client. When no `t:tls_client_auth_subject_value/0` is specified, defaults to
  `:tls_client_auth_subject_dn`
  - `:selfsigned_callback`: a `(String.t -> binary() | [binary()] | nil)`
  function that takes the `client_id` as a parameter and returns the certificate
  or the list of the certificate for `the client_id`, or `nil` if no certificate
  is registered for that client. Certificates can be returned in DER-encoded format, or
  native OTP certificate structure
  - `:cert_data_origin`: origin of the peer cert data. Can be set to:
    - `:native`: the peer certificate data is retrieved from the connection. Only works when
    this plug is used at the TLS termination endpoint. This is the *default value*
    - `{:header_param, "Header-Name"}`: the peer certificate data, and more specifically the
    parameter upon which the decision is to be made, is retrieved from an HTTP header. When
    using this feature, **make sure** that this header is filtered by a n upstream system
    (reverse-proxy...) so that malicious users cannot inject the value themselves. For instance,
    the configuration could be set to: `{:header_param, "SSL_CLIENT_DN"}`. If there are several
    values for the parameter (for instance several `dNSName`), they must be sent in
    separate headers. Not compatible with self-signed certiticate authentication
    - `:header_cert`: the whole certificate is forwarded in the `"Client-Cert"` HTTP header
    as a Base64 encoded value of the certificate's DER serialization, in conformance with
    [Client-Cert HTTP Header: Conveying Client Certificate Information from TLS Terminating Reverse Proxies to Origin Server Applications (draft-bdc-something-something-certificate-01)](https://tools.ietf.org/html/draft-bdc-something-something-certificate-01)
    - `{:header_cert, "Header-Name"}`: the whole certificate is forwarded in the
    "Header-Name" HTTP header as a Base64 encoded value of the certificate's DER serialization
    - `{:header_cert_pem, "Header-Name"}`: the whole certificate is forwarded in the
    "Header-Name" as a PEM-encoded string and retrieved by this plug
  - `:set_error_response`: function called when authentication failed. Defaults to
  `APIacAuthBasic.send_error_response/3`
  - `:error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
  Defaults to `:normal`

  ## Example

  ```elixir
  plug APIacAuthBasic, allowed_methods: :both,
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

  @type tls_client_auth_subject_value ::
  :tls_client_auth_subject_dn
  | :tls_client_auth_san_dns
  | :tls_client_auth_san_uri
  | :tls_client_auth_san_ip
  | :tls_client_auth_san_email

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
    |> Map.put_new(:cert_data_origin, :native)
    |> Map.put_new(:set_error_response, &APIacAuthMTLS.send_error_response/3)
    |> Map.put_new(:error_response_verbosity, :normal)
  end

  @impl Plug
  @spec call(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()
  def call(conn, %{} = opts) do
    if APIac.authenticated?(conn) do
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
      {:error, conn, %APIac.Authenticator.Unauthorized{} = error} ->
        opts[:set_error_response].(conn, error, opts)
    end
  end

  @doc """
  `APIac.Authenticator` credential extractor callback

  The returned credentials is a `{String.t, binary}` tuple where:
  - the first parameter is the `client_id`
  - the second parameter is the raw DER-encoded certificate
  """
  @impl APIac.Authenticator
  def extract_credentials(conn, opts) do
    with {:ok, conn, client_id} <- get_client_id(conn),
         {:ok, creds} <- do_extract_credentials(conn, opts) do
      {:ok, conn, {client_id, creds}}
    else
      {:error, conn, reason} ->
        {:error, conn,
         %APIac.Authenticator.Unauthorized{authenticator: __MODULE__, reason: reason}}
    end
  end

  defp get_client_id(%Plug.Conn{body_params: %Plug.Conn.Unfetched{}} = conn) do
    plug_parser_opts =
      Plug.Parsers.init(
        parsers: [:urlencoded],
        pass: ["application/x-www-form-urlencoded"]
      )

    conn
    |> Plug.Parsers.call(plug_parser_opts)
    |> get_client_id()
  rescue
    UnsupportedMediaTypeError ->
      {:error, conn, :unsupported_media_type}
  end

  defp get_client_id(conn) do
    client_id = conn.body_params["client_id"]

    cond do
      client_id == nil ->
        {:error, conn, :credentials_not_found}

      OAuth2Utils.valid_client_id_param?(client_id) == false ->
        {:error, conn, :invalid_client_id}

      true ->
        {:ok, conn, client_id}
    end
  end

  defp do_extract_credentials(conn, %{cert_data_origin: :native}) do
    case Plug.Conn.get_peer_data(conn)[:ssl_cert] do
      nil ->
        {:error, conn, :no_client_cert_authentication}

      raw_tls_cert ->
        {:ok, X509.Certificate.from_der!(raw_tls_cert)}
    end
  end

  defp do_extract_credentials(conn, %{cert_data_origin: {:header_param, header_name}}) do
    case Plug.Conn.get_req_header(conn, header_name) do
      [] ->
        {:error, conn, :no_header_value}

      headers ->
        {:ok, headers}
    end
  end

  defp do_extract_credentials(conn, %{cert_data_origin: :header_cert}) do
    do_extract_credentials(conn, %{cert_data_origin: {:header_cert, "Client-Cert"}})
  end

  defp do_extract_credentials(conn, %{cert_data_origin: {:header_cert, header_name}}) do
    case Plug.Conn.get_req_header(conn, String.downcase(header_name)) do
      [] ->
        {:error, conn, :no_cert_header_value}

      [b64_der_cert] ->
        with {:ok, der_cert} <- Base.decode64(b64_der_cert),
             {:ok, cert} <- X509.Certificate.from_der(der_cert)
        do
          {:ok, cert}
        else
          :error ->
            {:error, :invalid_b64_encoding_der_cert}

          {:error, _} ->
            {:error, :invalid_der_cert}
        end

      [_ | _] ->
        {:error, conn, :multiple_certs_in_header}
    end
  end

  defp do_extract_credentials(conn, %{cert_data_origin: {:header_cert_pem, header_name}}) do
    case Plug.Conn.get_req_header(conn, String.downcase(header_name)) do
      [] ->
        {:error, conn, :no_cert_header_value}

      [pem_cert] ->
        case X509.Certificate.from_pem(pem_cert) do
          {:ok, cert} ->
            {:ok, cert}

          {:error, _} ->
            {:error, :invalid_pem_cert}
        end

      [_ | _] ->
        {:error, conn, :multiple_certs_in_header}
    end
  end

  @doc """
  `APIac.Authenticator` credential validator callback

  The credentials parameter must be an `%X509.Certificate{}` struct
  """
  @impl APIac.Authenticator
  def validate_credentials(conn, {client_id, {:OTPCertificate, _, _, _} = cert}, opts) do
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
         %APIac.Authenticator.Unauthorized{
           authenticator: __MODULE__,
           reason: :no_method_provided
         }}
      end
    end
  end

  def validate_credentials(_conn, {_client_id, header_values}, %{allowed_methods: :selfsigned})
    when is_list(header_values)
  do
    raise ~s({:header_param, "Header-Name} is unsupported for self-signed certificates)
  end

  def validate_credentials(conn, {client_id, header_values}, opts) when is_list(header_values) do
    case opts[:pki_callback].(client_id) do
      {_tls_client_auth_subject_value_parameter, expected} ->
        expected in header_values

      expected when is_binary(expected) ->
        expected in header_values

      nil ->
        false
    end
    |> if do
      conn =
        conn
        |> Plug.Conn.put_private(:apiac_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apiac_client, client_id)

      {:ok, conn}
    else
      {:error, conn,
       %APIac.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :pki_no_match}}
    end
  end

  defp validate_self_signed_cert(conn, client_id, cert, opts) do
    peer_cert_subject_public_key= X509.Certificate.public_key(cert)

    registered_certs =
      case opts[:selfsigned_callback].(client_id) do
        nil ->
          []

        [_ | _] = certs ->
          certs

        cert ->
          [cert]
      end

    public_key_info_match =
      Enum.any?(
        registered_certs,
        fn registered_cert ->
          case registered_cert do
            {:OTPCertificate, _, _, _} ->
              registered_cert

            der_cert when is_binary(der_cert) ->
              X509.Certificate.from_der!(der_cert)
          end
          |> X509.Certificate.public_key() == peer_cert_subject_public_key
        end
      )

    if public_key_info_match do
      conn =
        conn
        |> Plug.Conn.put_private(:apiac_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apiac_client, client_id)

      {:ok, conn}
    else
      {:error, conn,
       %APIac.Authenticator.Unauthorized{
         authenticator: __MODULE__,
         reason: :selfsigned_no_cert_match
       }}
    end
  rescue
    _ -> {:error, conn, %APIac.Authenticator.Unauthorized{
           authenticator: __MODULE__,
           reason: :unknown
       }}
  end

  defp validate_pki_cert(conn, client_id, cert, opts) do
    case opts[:pki_callback].(client_id) do
      {tls_client_auth_subject_value_parameter, parameter_value} ->
        do_validate_pki_cert(tls_client_auth_subject_value_parameter, cert, parameter_value)

      parameter_value when is_binary(parameter_value) ->
        do_validate_pki_cert(:tls_client_auth_subject_dn, cert, parameter_value)

      _ ->
        false
    end
    |> if do
      conn =
        conn
        |> Plug.Conn.put_private(:apiac_authenticator, __MODULE__)
        |> Plug.Conn.put_private(:apiac_client, client_id)

      {:ok, conn}
    else
      {:error, conn,
       %APIac.Authenticator.Unauthorized{authenticator: __MODULE__, reason: :pki_no_match}}
    end
  end

  defp do_validate_pki_cert(:tls_client_auth_subject_dn, cert, dn) do
    # FIXME: is comparing string serialization of this DNs ok on a security
    # point of view? Or shall we compare the raw SDNs?
    # See further https://tools.ietf.org/html/rfc5280#section-7.1
    cert
    |> X509.Certificate.subject()
    |> X509.RDNSequence.to_string() == dn
  end

  defp do_validate_pki_cert(tls_client_auth_subject_value_parameter, cert, param_value) do
    san_key =
      case tls_client_auth_subject_value_parameter do
        :tls_client_auth_san_dns -> :dNSName
        :tls_client_auth_san_uri -> :uniformResourceIdentifier
        :tls_client_auth_san_ip -> :iPAddress
        :tls_client_auth_san_email -> :rfc822Name
      end

    cert
    |> X509.Certificate.extension(:subject_alt_name)
    |> case do
      nil ->
        false

      {:Extension, {2, 5, 29, 17}, false, values} ->
        values
        |> Enum.filter(fn {k, _v} -> k == san_key end)
        |> Enum.any?(fn {_k, v} -> param_value == List.to_string(v) end)
    end
  end

  @doc """
  Implementation of the `APIac.Authenticator` callback

  ## Verbosity

  The following elements in the HTTP response are set depending on the value
  of the `:error_response_verbosity` option:

  | Error response verbosity  | HTTP Status        | Headers | Body                                                    |
  |:-------------------------:|--------------------|---------|---------------------------------------------------------|
  | `:debug`                  | Unauthorized (401) |         | `APIac.Authenticator.Unauthorized` exception's message |
  | `:normal`                 | Unauthorized (401) |         |                                                         |
  | `:minimal`                | Unauthorized (401) |         |                                                         |

  """
  @impl APIac.Authenticator
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

  See the `APIac.AuthFailureResponseData` module for more information.
  """
  @spec save_authentication_failure_response(Plug.Conn.t(),
                                             %APIac.Authenticator.Unauthorized{},
                                             any()) :: Plug.Conn.t()
  def save_authentication_failure_response(conn, error, opts) do
    failure_response_data =
      %APIac.AuthFailureResponseData{
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

    APIac.AuthFailureResponseData.put(conn, failure_response_data)
  end
end
