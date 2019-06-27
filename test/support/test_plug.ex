defmodule TestPlug do
  defmacro __using__(args) do
    quote bind_quoted: [args: args] do
      use Plug.Builder
      plug(APIacAuthMTLS, args)
      plug(:index)

      defp index(%Plug.Conn{status: 401} = conn, _opts) do
        conn |> send_resp()
      end

      defp index(conn, _opts) do
        conn |> send_resp(200, Poison.encode!(conn.private))
      end
    end
  end
end
