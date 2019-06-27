defmodule TestHelperFunctions do
  def test_dn(_client_id),
    do: "/C=BZ/ST=MBH/L=Lorient/O=APIacAuthBearer/CN=test peer certificate"

  def cert_from_ets(_client_id) do
    :ets.lookup_element(:mtls_test, :cert, 2)
  end
end
