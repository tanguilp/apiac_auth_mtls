defmodule TestHelperFunctions do
  def test_dn(_client_id),
    do: "/C=BZ/ST=MBH/L=Lorient/O=APIacAuthBearer/CN=test peer certificate"

  def test_dns(_client_id),
    do: {:tls_client_auth_san_dns, "www.example.org"}

  def test_email(_client_id),
    do: {:tls_client_auth_san_email, "john@example.org"}

  def cert_from_ets(_client_id) do
    :ets.lookup_element(:mtls_test, :cert, 2)
  end
end
