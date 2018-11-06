# APISexAuthMTLS

** WIP - do not use in prod env **

An `APISex.Authenticator` plug implementing [RFCXXXX](https://tools.ietf.org/html/draft-ietf-oauth-mtls-12)
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
- `set_authn_error_response`: if `true`, sets the HTTP status code to `401`.
If false, does not change them. Defaults to `true`
- `halt_on_authn_failure`: if set to `true`, halts the connection and directly sends the
response. When set to `false`, does nothing and therefore allows chaining several
authenticators. Defaults to `true`

## Example

```elixir
Plug APISexAuthBasic, allowed_methods: :both,
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
