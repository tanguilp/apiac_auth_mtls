defmodule APISexAuthMTLSTest do
  # as we are using the registry for testing, we have to disable async
  # so as to avoir race conditions
  use ExUnit.Case, async: false
  doctest APISexAuthMTLS

  defmodule PKICert do
    use TestPlug, [allowed_methods: :pki, pki_callback: &TestHelperFunctions.test_dn/1]
  end

  defmodule SelfSignedCert do
    use TestPlug, [allowed_methods: :selfsigned, selfsigned_callback: &TestHelperFunctions.cert_from_ets/1]
  end

  setup_all do
    :ets.new(:mtls_test, [:set, :public, :named_table])
    :inets.start()

    :ok
  end

  setup do
    ref = make_ref()

    on_exit fn ->
      Plug.Cowboy.shutdown(ref)
    end

    [ref: ref]
  end

  test "valid pki certificate", context do
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
         peer_root_cert, peer_root_private_key
         )

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca)

    Plug.Cowboy.https(PKICert, [],
                      port: 8443,
                      ref: context[:ref],
                      cert: X509.Certificate.to_der(server_ca_cert),
                      cacerts: [X509.Certificate.to_der(peer_root_cert)],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
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
    assert Poison.decode!(body)["apisex_client"] == "testclient"
    assert Poison.decode!(body)["apisex_authenticator"] == "Elixir.APISexAuthMTLS"
  end

  test "invalid pki certificate", context do
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
         "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=invalid DN",
         peer_root_cert, peer_root_private_key
         )

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca)

    Plug.Cowboy.https(PKICert, [],
                      port: 8443,
                      ref: context[:ref],
                      cert: X509.Certificate.to_der(server_ca_cert),
                      cacerts: [X509.Certificate.to_der(peer_root_cert)],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
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

    assert elem(status, 1) == 401
    assert body == []
  end

  test "valid self-signed certificate (DER-encoded)", context do

    peer_private_key = X509.PrivateKey.new_ec(:secp256r1)
    peer_cert = X509.Certificate.self_signed(peer_private_key,
      "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=test self-signed CA peer certificate",
      template: :server
    )

    :ets.insert(:mtls_test, {:cert, X509.Certificate.to_der(peer_cert)})

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca,
      extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["localhost"])])

    Plug.Cowboy.https(SelfSignedCert, [],
                      port: 8443,
                      ref: context[:ref],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
                      cert: X509.Certificate.to_der(server_ca_cert),
                      verify: :verify_peer,
                      verify_fun: {&verify_fun_selfsigned_cert/3, []}
    )

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
    assert Poison.decode!(body)["apisex_client"] == "testclient"
    assert Poison.decode!(body)["apisex_authenticator"] == "Elixir.APISexAuthMTLS"
  end

  test "valid self-signed certificate (OTP certificate struct)", context do

    peer_private_key = X509.PrivateKey.new_ec(:secp256r1)
    peer_cert = X509.Certificate.self_signed(peer_private_key,
      "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=test self-signed CA peer certificate",
      template: :server
    )

    :ets.insert(:mtls_test, {:cert, peer_cert})

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca,
      extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["localhost"])])

    Plug.Cowboy.https(SelfSignedCert, [],
                      port: 8443,
                      ref: context[:ref],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
                      cert: X509.Certificate.to_der(server_ca_cert),
                      verify: :verify_peer,
                      verify_fun: {&verify_fun_selfsigned_cert/3, []}
    )

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
    assert Poison.decode!(body)["apisex_client"] == "testclient"
    assert Poison.decode!(body)["apisex_authenticator"] == "Elixir.APISexAuthMTLS"
  end

  test "invalid self-signed certificate", context do

    peer_private_key = X509.PrivateKey.new_ec(:secp256r1)
    peer_cert = X509.Certificate.self_signed(peer_private_key,
      "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=test self-signed CA peer certificate",
      template: :server
    )

    invalid_peer_private_key = X509.PrivateKey.new_ec(:secp256r1)
    invalid_peer_cert = X509.Certificate.self_signed(invalid_peer_private_key,
      "/C=BZ/ST=MBH/L=Lorient/O=APISexAuthBearer/CN=test self-signed CA peer certificate",
      template: :server
    )
    :ets.insert(:mtls_test, {:cert, X509.Certificate.to_der(invalid_peer_cert)})

    server_ca_private_key = X509.PrivateKey.new_ec(:secp256r1)
    server_ca_cert = X509.Certificate.self_signed(server_ca_private_key,
      "/C=RU/ST=SPB/L=SPB/O=APISexAuthBearer/CN=test server certificate",
      template: :root_ca,
      extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["localhost"])])

    Plug.Cowboy.https(SelfSignedCert, [],
                      port: 8443,
                      ref: context[:ref],
                      key: {:ECPrivateKey, X509.PrivateKey.to_der(server_ca_private_key)},
                      cert: X509.Certificate.to_der(server_ca_cert),
                      verify: :verify_peer,
                      verify_fun: {&verify_fun_selfsigned_cert/3, []}
    )

    {:ok, {status, _headers, body}} =
      :httpc.request(:post,
      {'https://localhost:8443', [], 'application/x-www-form-urlencoded', 'client_id=testclient'},
      [ssl: [
        cacerts: [X509.Certificate.to_der(server_ca_cert)],
        cert: X509.Certificate.to_der(peer_cert),
        key: {:ECPrivateKey, X509.PrivateKey.to_der(peer_private_key)}
      ]],
      [])

    assert elem(status, 1) == 401
    assert body == []
  end

  #FIXME should we make it an exported function in main lib?
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
end
