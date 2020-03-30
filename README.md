# APIacAuthMTLS

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

## Installation

```elixir
def deps do
  [
    {:apiac_auth_mtls, github: "tanguilp/apiac_auth_mtls", tag: "0.3.0"}
  ]
end
```

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

## Configuring TLS for client authentication

See the module's information for further information, examples, and the security considerations.
