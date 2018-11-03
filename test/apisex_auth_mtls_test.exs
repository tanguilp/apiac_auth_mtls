defmodule APISexAuthMTLSTest do
  # as we are using the registry for testing, we have to disable async
  # so as to avoir race conditions
  use ExUnit.Case, async: false
  doctest APISexAuthMTLS

  defmodule SelfSignedValidCert do
    use TestPlug, [allowed_methods: :pki, pki_callback: &TestHelperFunctions.test_dn/1]
  end

  setup_all do
    :ets.new(:mtls_test, [:set, :public])
    :inets.start()

    :ok
  end

  test "valid pki certificate" do
    peer_root_private_key = X509.PrivateKey.new_ec(:secp256r1)
    peer_root_cert = X509.Certificate.self_signed(peer_root_private_key,
      "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=test root CA peer certificate",
      template: :root_ca
    )

    peer_private_key = X509.PrivateKey.new_ec(:secp256r1)
    peer_cert =
      peer_private_key
      |> X509.PublicKey.derive()
      |> X509.Certificate.new(
         "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=test peer certificate",
         peer_root_cert, peer_root_private_key,
         extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["localhost"])])

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca)

    res = Plug.Cowboy.https(SelfSignedValidCert, [],
                      port: 8443,
                      cert: X509.Certificate.to_der(server_ca_cert),
                      cacerts: [X509.Certificate.to_der(peer_root_cert)],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
                      #fail_if_no_peer_cert: true,
                      verify: :verify_peer)

    {:ok, {status, _headers, body}} =
      :httpc.request(:post,
      {'https://localhost:8443', [], 'application/x-www-form-urlencoded', 'client_id=testclient'},
      [ssl: [
        cacerts: [X509.Certificate.to_der(server_ca_cert)],
        cert: X509.Certificate.to_der(peer_cert),
        key: {:ECPrivateKey, X509.PrivateKey.to_der(peer_private_key)}
      ]],
      [])


    assert elem(status, 1) == 200
  end
end
