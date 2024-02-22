defmodule Electric.Replication.PostgresConnectorSup do
  use Supervisor
  require Logger

  alias Electric.Replication.Connectors
  alias Electric.Replication.Postgres
  alias Electric.Postgres.Extension.SchemaCache
  alias Electric.Replication.SatelliteCollectorProducer

  @spec start_link(Connectors.config()) :: :ignore | {:error, any} | {:ok, pid}
  def start_link(connector_config) do
    Supervisor.start_link(__MODULE__, connector_config)
  end

  @spec name(Connectors.origin()) :: Electric.reg_name()
  def name(origin) when is_binary(origin) do
    Electric.name(__MODULE__, origin)
  end

  @impl Supervisor
  def init(connector_config) do
    origin = Connectors.origin(connector_config)
    name = name(origin)
    Electric.reg(name)

    write_to_pg_mode = Connectors.write_to_pg_mode(connector_config)

    ###

    pool_module = Electric.Postgres.ConnectionPool
    start_args = [connector_config, [name: pool_module]]
    connection_pool_spec = %{id: pool_module, start: {pool_module, :start_link, start_args}}

    ###

    schema_cache_spec = {SchemaCache, connector_config}

    ###

    opts = [name: SatelliteCollectorProducer.name(), write_to_pg_mode: write_to_pg_mode]
    satellite_collector_producer_spec = {SatelliteCollectorProducer, opts}

    ###

    logical_replication_producer_spec = {Postgres.LogicalReplicationProducer, connector_config}

    ###

    opts = [
      producer: Postgres.LogicalReplicationProducer.name(origin),
      refresh_subscription: write_to_pg_mode == :logical_replication
    ]

    migration_consumer_spec =
      %{
        id: Postgres.MigrationConsumer,
        start: {Postgres.MigrationConsumer, :start_link, [connector_config, opts]}
      }

    ###

    pg_writer_config = [
      conn_config: connector_config,
      producer: SatelliteCollectorProducer.name()
    ]

    pg_writer_spec =
      if write_to_pg_mode == :logical_replication do
        {Postgres.SlotServer, pg_writer_config}
      else
        {Postgres.Writer, pg_writer_config}
      end

    ###

    # Uses a globally registered name
    cached_wal_spec =
      {Electric.Postgres.CachedWal.EtsBacked,
       wal_window_size: Connectors.get_wal_window_opts(connector_config).in_memory_size,
       subscribe_to: [{Postgres.MigrationConsumer.name(origin), []}]}

    ###

    migrations_proxy_spec = {Electric.Postgres.Proxy, connector_config: connector_config}

    children = [
      connection_pool_spec,
      schema_cache_spec,
      satellite_collector_producer_spec,
      logical_replication_producer_spec,
      migration_consumer_spec,
      pg_writer_spec,
      # TODO: add a new process here that will process replication messages and
      # decide when to drop cached wal window and advance the primary replication slot
      # to keep the resumable wal window in check.
      cached_wal_spec,
      migrations_proxy_spec
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
