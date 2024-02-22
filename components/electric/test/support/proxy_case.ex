defmodule Electric.Proxy.Case do
  defmacro __using__(opts) do
    quote do
      use ExUnit.Case, unquote(opts)

      alias Electric.Postgres.ConnectionPool
      alias Electric.Postgres.Extension.SchemaLoader

      import Electric.Postgres.TestConnection

      setup do
        context = create_test_db()

        assert {:ok, _versions} = Electric.Postgres.Extension.migrate(context.conn)

        port = 9931
        loader = {SchemaLoader.Epgsql, []}

        connector_config = [
          origin: "my_origin",
          connection: context.conn_opts,
          proxy: [password: "password", listen: [port: port]]
        ]

        start_link_supervised!(%{
          id: ConnectionPool,
          start: {ConnectionPool, :start_link, [connector_config, [name: ConnectionPool]]}
        })

        start_link_supervised!({Electric.Postgres.Proxy,
         connector_config: connector_config,
         handler_config: [
           loader: loader
           # injector: [capture_mode: Electric.Postgres.Proxy.Injector.Capture.Transparent]
         ]})

        start_link_supervised!(
          {Electric.Postgres.Proxy.TestRepo,
           Keyword.merge(context.pg_config, port: port, pool_size: 2)}
        )

        {:ok, Map.merge(context, %{repo: Electric.Postgres.Proxy.TestRepo})}
      end
    end
  end
end
