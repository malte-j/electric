defmodule Electric.Postgres.ConnectionPool do
  @moduledoc false

  alias Electric.Replication.{Connectors, Postgres.Client}

  require Logger

  @behaviour NimblePool

  @checkout_timeout 5_000

  def start_link(connector_config, opts) do
    # IO.puts("Connection.start_link(#{inspect(connector_config)}, #{inspect(opts)})")

    NimblePool.start_link(
      worker: {__MODULE__, Connectors.get_connection_opts(connector_config)},
      # only connect when required, not immediately
      lazy: true,
      pool_size: 4,
      worker_idle_timeout: 30_000,
      name: opts[:name]
    )
  end

  def exec_fun!(pool \\ __MODULE__, fun, timeout \\ @checkout_timeout)
      when is_pid(pool) or (is_atom(pool) and is_function(fun, 1)) do
    # IO.puts("exec_fun!(#{inspect(pool)}, #{inspect(fun)}, #{inspect(timeout)})")
    NimblePool.checkout!(pool, :checkout, fn _pool, conn -> {fun.(conn), :ok} end, timeout)
  end

  @impl NimblePool
  def init_worker(conn_opts) do
    # IO.puts("init_worker(#{inspect(conn_opts)})")

    {:ok, conn} =
      Client.connect(conn_opts)

    # |> IO.inspect()

    {:ok, conn, conn_opts}
  end

  @impl NimblePool
  # Transfer the port to the caller
  def handle_checkout(:checkout, _from, conn, pool_state) do
    {:ok, conn, conn, pool_state}
  end

  @impl NimblePool
  def handle_checkin(:ok, _from, conn, pool_state) do
    {:ok, conn, pool_state}
  end

  @impl NimblePool
  def terminate_worker(_reason, conn, pool_state) do
    Logger.debug("Terminating idle db connection #{inspect(conn)}")
    Client.close(conn)
    {:ok, pool_state}
  end

  @impl NimblePool
  def handle_ping(_conn, _pool_state) do
    {:remove, :idle}
  end
end
