defmodule Electric.Postgres.Extension.SchemaLoader.Epgsql do
  @moduledoc """
  Implements the SchemaLoader behaviour backed by the connected
  postgres instance.

  Uses a connection pool to avoid deadlocks when e.g. refreshing a subscription
  then attempting to run a query against the db.
  """
  alias Electric.Postgres.{ConnectionPool, Extension, Extension.SchemaLoader, Schema}
  alias Electric.Replication.Postgres.Client

  require Logger

  @behaviour SchemaLoader

  @pool_timeout 5_000

  @impl true
  def connect(conn_config, opts) do
    # IO.puts("connect(#{inspect(conn_config)}, #{inspect(opts)})")
    {:ok, {__MODULE__, conn_config, opts}}
  end

  defp checkout!(state, fun) do
    {__MODULE__, conn_config, _opts} = state

    # IO.puts("checkout!(#{inspect(state)}, #{inspect(fun)})")

    # NOTE: use `__connection__: conn` in tests to pass an existing connection
    case Keyword.fetch(conn_config, :__connection__) do
      {:ok, conn} -> fun.(conn)
      :error -> ConnectionPool.exec_fun!(ConnectionPool, fun, @pool_timeout)
    end
  end

  @impl true
  def load(pool) do
    checkout!(pool, fn conn ->
      with {:ok, version, schema} <- Extension.current_schema(conn) do
        {:ok, SchemaLoader.Version.new(version, schema)}
      end
    end)
  end

  @impl true
  def load(pool, version) do
    checkout!(pool, fn conn ->
      with {:ok, version, schema} <- Extension.schema_version(conn, version) do
        {:ok, SchemaLoader.Version.new(version, schema)}
      end
    end)
  end

  @impl true
  def save(pool, version, schema, stmts) do
    checkout!(pool, fn conn ->
      with :ok <- Extension.save_schema(conn, version, schema, stmts) do
        {:ok, pool, SchemaLoader.Version.new(version, schema)}
      end
    end)
  end

  @impl true
  def relation_oid(_conn, :trigger, _schema, _table) do
    raise RuntimeError, message: "oid lookup for triggers no implemented"
  end

  def relation_oid(pool, rel_type, schema, table) do
    checkout!(pool, fn conn ->
      Client.relation_oid(conn, rel_type, schema, table)
    end)
  end

  @impl true
  def refresh_subscription(pool, name) do
    checkout!(pool, fn conn ->
      query = ~s|ALTER SUBSCRIPTION "#{name}" REFRESH PUBLICATION WITH (copy_data = false)|

      case :epgsql.squery(conn, query) do
        {:ok, [], []} ->
          :ok

        # "ALTER SUBSCRIPTION ... REFRESH is not allowed for disabled subscriptions"
        # ignore this as it's due to race conditions with the rest of the system
        {:error, {:error, :error, "55000", :object_not_in_prerequisite_state, _, _}} ->
          Logger.warning("Unable to refresh DISABLED subscription #{name}")
          :ok

        error ->
          error
      end
    end)
  end

  @impl true
  def migration_history(pool, version) do
    checkout!(pool, fn conn ->
      Extension.migration_history(conn, version)
    end)
  end

  @impl true
  def known_migration_version?(pool, version) do
    checkout!(pool, fn conn ->
      Extension.known_migration_version?(conn, version)
    end)
  end

  @impl true
  def internal_schema(pool) do
    checkout!(pool, fn conn ->
      oid_loader = &Client.relation_oid(conn, &1, &2, &3)

      Enum.reduce(Extension.replicated_table_ddls(), Schema.new(), fn ddl, schema ->
        Schema.update(schema, ddl, oid_loader: oid_loader)
      end)
    end)
  end

  @impl true
  def table_electrified?(pool, {schema, name}) do
    # IO.puts("outside table_electrified?(#{inspect(schema)}, #{inspect(name)})")

    checkout!(pool, fn conn ->
      # IO.puts("inside table_electrified?(#{inspect(schema)}, #{inspect(name)})")
      Extension.electrified?(conn, schema, name)
    end)
  end

  @impl true
  def index_electrified?(pool, {schema, name}) do
    checkout!(pool, fn conn ->
      Extension.index_electrified?(conn, schema, name)
    end)
  end

  @impl true
  def tx_version(pool, row) do
    checkout!(pool, fn conn ->
      Extension.tx_version(conn, row)
    end)
  end
end
