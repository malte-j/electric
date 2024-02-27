defmodule Electric.Postgres.CachedWal.EtsBacked do
  @moduledoc """
  ETS-backed WAL cache.

  This cache is implemented as a GenStage consumer, so it should be subscribed to a producer that sends
  `t:Transaction.t()` structs as events. This consumer will then fill and update the cache from the stream.

  ## `start_link/1` options

  - `name`: GenServer process name
  - `max_cache_count`: maximum count of WAL entries to store in cache. When maximum is reached, a cleanup will be performed,
    removing oldest entries (FIFO)
  """

  require Logger
  alias Electric.Replication.Changes.Transaction
  alias Electric.Postgres.Lsn
  alias Electric.Postgres.CachedWal.Api

  use GenStage
  @behaviour Electric.Postgres.CachedWal.Api

  @ets_table_name :ets_backed_cached_wal

  @typep state :: %{
           wal_window_size: non_neg_integer(),
           notification_requests: %{optional(reference()) => {Api.wal_pos(), pid()}},
           table: :ets.table(),
           last_seen_wal_pos: Api.wal_pos(),
           current_tx_count: non_neg_integer()
         }

  # Public API

  @doc """
  Start the cache. See module docs for options
  """
  def start_link(opts) do
    # We're globally registering this process since ets table name is hardcoded anyway, so no two instances can be started.
    GenStage.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def clear_cache(stage) do
    GenStage.cast(stage, :clear_cache)
  end

  @impl Api
  def lsn_in_cached_window?(client_wal_pos) do
    # TODO
    case :ets.first(@ets_table_name) do
      :"$end_of_table" ->
        false

      first_position ->
        case :ets.last(@ets_table_name) do
          :"$end_of_table" ->
            false

          last_position ->
            first_position <= client_wal_pos and client_wal_pos <= last_position
        end
    end
  end

  @impl Api
  def get_current_position do
    with :"$end_of_table" <- :ets.last(@ets_table_name) do
      nil
    end
  end

  @impl Api
  def next_segment(wal_pos) do
    case :ets.next(@ets_table_name, wal_pos) do
      :"$end_of_table" -> :latest
      key -> {:ok, :ets.lookup_element(@ets_table_name, key, 2), key}
    end
  end

  @impl Api
  def request_notification(wal_pos) do
    GenStage.call(__MODULE__, {:request_notification, wal_pos})
  end

  @impl Api
  def cancel_notification_request(ref) do
    GenStage.call(__MODULE__, {:cancel_notification, ref})
  end

  @impl Api
  def serialize_wal_position(wal_pos), do: Integer.to_string(wal_pos)

  @impl Api
  def parse_wal_position(binary) do
    case Integer.parse(binary) do
      {num, ""} -> {:ok, num}
      _ -> :error
    end
  end

  @impl Api
  def telemetry_stats() do
    GenStage.call(__MODULE__, :telemetry_stats)
  catch
    :exit, _ -> nil
  end

  # Internal API

  @impl GenStage
  def init(opts) do
    set = :ets.new(@ets_table_name, [:named_table, :ordered_set])
    Logger.metadata(component: "CachedWal.EtsBacked")

    state = %{
      wal_window_size: Keyword.fetch!(opts, :wal_window_size),
      notification_requests: %{},
      table: set,
      last_seen_wal_pos: 0,
      current_tx_count: 0
    }

    case Keyword.get(opts, :subscribe_to) do
      nil -> {:consumer, state}
      subscription -> {:consumer, state, subscribe_to: subscription}
    end
  end

  @impl GenStage
  def handle_call({:request_notification, wal_pos}, {from, _}, state) do
    ref = make_ref()
    state = Map.update!(state, :notification_requests, &Map.put(&1, ref, {wal_pos, from}))

    if wal_pos < state.last_seen_wal_pos do
      send(self(), :fulfill_notifications)
    end

    {:reply, {:ok, ref}, [], state}
  end

  def handle_call({:cancel_notification, ref}, _, state) do
    state = Map.update!(state, :notification_requests, &Map.delete(&1, ref))

    {:reply, :ok, [], state}
  end

  def handle_call(:telemetry_stats, _from, state) do
    oldest_timestamp =
      if tx = lookup_oldest_transaction(state.table) do
        tx.commit_timestamp
      end

    stats = %{
      transaction_count: state.current_tx_count,
      oldest_transaction_timestamp: oldest_timestamp,
      max_cache_size: state.wal_window_size,
      cache_memory_total: :ets.info(state.table, :memory) * :erlang.system_info(:wordsize)
    }

    {:reply, stats, [], state}
  end

  def handle_call({:insert_transactions, txs}, _from, state) do
    {:noreply, [], state} = handle_events(txs, nil, state)
    {:reply, :ok, state}
  end

  @impl GenStage
  def handle_cast(:clear_cache, state) do
    :ets.delete_all_objects(state.table)

    # This doesn't do anything with notification requests, but this function is not meant to be used in production
    {:noreply, [], %{state | current_tx_count: 0, last_seen_wal_pos: 0}}
  end

  @impl GenStage
  @spec handle_events([Transaction.t()], term(), state()) :: {:noreply, [], any}
  def handle_events(events, _, state) do
    events
    # TODO: Make sure that when this process crashes, LogicalReplicationProducer is restarted as well
    # in order to fill up the in-memory cache. Use the one_for_all supervisor strategy.
    |> Stream.each(& &1.ack_fn.())
    # TODO: We're currently storing & streaming empty transactions to Satellite, which is not ideal, but we need
    #       to be aware of all transaction IDs and LSNs that happen, otherwise flakiness begins. I don't like that,
    #       so we probably want to be able to store a shallower pair than a full transaction object and handle that
    #       appropriately in the consumers. Or something else.
    |> Stream.each(
      &Logger.debug(
        "Saving transaction #{&1.xid} at #{&1.lsn} with changes #{inspect(&1.changes)}"
      )
    )
    |> Stream.map(fn %Transaction{lsn: lsn} = tx ->
      {lsn_to_position(lsn), %{tx | ack_fn: nil}}
    end)
    |> Enum.to_list()
    |> tap(&:ets.insert(state.table, &1))
    |> List.last()
    |> case do
      nil ->
        # All transactions were empty
        {:noreply, [], state}

      {position, _} ->
        state =
          state
          |> Map.put(:last_seen_wal_pos, position)
          |> fulfill_notification_requests()
          |> trim_cache()

        {:noreply, [], state}
    end
  end

  @impl GenStage
  def handle_info(:fulfill_notifications, state) do
    {:noreply, [], fulfill_notification_requests(state)}
  end

  @spec fulfill_notification_requests(state()) :: state()
  defp fulfill_notification_requests(%{last_seen_wal_pos: new_max_lsn} = state) do
    fulfilled_refs =
      state.notification_requests
      |> Stream.filter(fn {_, {target, _}} -> target <= new_max_lsn end)
      |> Stream.each(fn {ref, {_, pid}} ->
        send(pid, {:cached_wal_notification, ref, :new_segments_available})
      end)
      |> Enum.map(&elem(&1, 0))

    Map.update!(state, :notification_requests, &Map.drop(&1, fulfilled_refs))
  end

  def lsn_to_position(lsn), do: Lsn.to_integer(lsn)

  # Drop all transactions from the cache whose position is less than the last transaction's
  # position minus in-memory WAL window size.
  @spec trim_cache(state()) :: state()
  defp trim_cache(state) do
    first_in_window_pos = state.last_seen_wal_pos - state.wal_window_size

    :ets.select_delete(state.table, [
      {{:"$1", :_}, [{:<, :"$1", first_in_window_pos}], [:"$1"]}
    ])

    %{state | current_tx_count: :ets.info(state.table, :size)}
  end

  defp lookup_oldest_transaction(ets_table) do
    case :ets.match(ets_table, {:_, :"$1"}, 1) do
      {[[%Transaction{} = tx]], _cont} -> tx
      :"$end_of_table" -> nil
    end
  end
end
