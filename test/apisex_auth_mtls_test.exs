defmodule APISexAuthMTLSTest do
  # as we are using the registry for testing, we have to disable async
  # so as to avoir race conditions
  use ExUnit.Case, async: false
  doctest APISexAuthMTLS

  defmodule SelfSignedValidCert do
    use TestPlug, [allowed_methods: :pki, pki_callback: &TestHelperFunctions.cert_from_ets/1]
  end

  setup_all do
    :ets.new(:mtls_test, [:set, :public])
    :inets.start()

    :ok
  end

  test "valid self-signed certificate" do
    peer_private_key = X509.PrivateKey.new_ec(:secp256r1)
    peer_cert = X509.Certificate.self_signed(peer_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test peer certificate",
      template: :root_ca)

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca)

    res = Plug.Cowboy.https(SelfSignedValidCert, [],
                      port: 8443,
                      cert: X509.Certificate.to_der(server_ca_cert),
                      cacerts: [X509.Certificate.to_der(peer_cert)],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
                      verify: :verify_peer)

    IO.inspect(res)
    {:ok, {status, _headers, body}} =
      :httpc.request(:post,
      {'https://localhost:8443', [], 'application/x-www-form-urlencoded', 'client_id=clientname'},
      [ssl: [
        cacerts: [X509.Certificate.to_der(server_ca_cert)],
        cert: X509.Certificate.to_der(peer_cert),
        key: {:ECPrivateKey, X509.PrivateKey.to_der(peer_private_key)}
      ]],
      [])


    assert elem(status, 1) == 200
  end
end
