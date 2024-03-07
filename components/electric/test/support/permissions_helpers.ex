defmodule ElectricTest.PermissionsHelpers do
  defmodule Auth do
    def user_id do
      "92bafe18-a818-4a3f-874f-590324140478"
    end

    def user(id \\ user_id()) do
      %Electric.Satellite.Auth{user_id: id}
    end

    def nobody do
      %Electric.Satellite.Auth{user_id: nil}
    end
  end

  defmodule Perms do
    alias Electric.Satellite.SatPerms, as: P
    alias Electric.Satellite.Permissions

    defmodule Transient do
      @name __MODULE__.Transient

      def name do
        Process.get(__MODULE__)
      end

      def unique_name do
        id = System.unique_integer([:positive, :monotonic])
        Module.concat([@name, :"Instance_#{id}"])
      end

      def child_spec(_init_arg) do
        name = unique_name()

        default = %{
          id: @name,
          start: {Permissions.Transient, :start_link, [[name: name]]}
        }

        Process.put(__MODULE__, name)

        Supervisor.child_spec(default, [])
      end
    end

    def new(attrs \\ []) do
      auth = Keyword.get(attrs, :auth, Auth.user())

      Permissions.new(auth, Transient.name())
    end

    def update(perms, schema_version, ddlx, roles) do
      Permissions.update(
        perms,
        schema_version,
        to_rules(ddlx),
        roles
      )
    end

    def transient(attrs) do
      Permissions.Transient.new(attrs)
    end

    def add_transient(perms, attrs) do
      Permissions.Transient.update([transient(attrs)], Transient.name())
      perms
    end

    def to_rules(ddlx) do
      ddlx
      |> List.wrap()
      |> Enum.map(fn
        "ELECTRIC " <> _ = ddlx -> ddlx
        ddl -> "ELECTRIC " <> ddl
      end)
      |> Enum.map(&Electric.DDLX.parse!/1)
      |> Enum.reduce(
        {%P.Rules{}, {1, 1}},
        fn %{cmds: %{assigns: assigns, grants: grants}}, {rules, {assign_id, grant_id}} ->
          # give all the rules deterministic ids based on order
          # which makes it easier to assign roles to rules in tests
          {assigns, assign_id} =
            Enum.map_reduce(assigns, assign_id, fn assign, id ->
              {%{assign | id: "assign-#{id}"}, id + 1}
            end)

          {grants, grant_id} =
            Enum.map_reduce(grants, grant_id, fn grant, id ->
              {%{grant | id: "grant-#{id}"}, id + 1}
            end)

          {%{
             rules
             | assigns: rules.assigns ++ assigns,
               grants: rules.grants ++ grants
           }, {assign_id, grant_id}}
        end
      )
      |> then(&elem(&1, 0))
    end
  end

  defmodule LSN do
    def new(lsn) when is_integer(lsn) do
      Electric.Postgres.Lsn.from_integer(lsn)
    end

    def new(nil) do
      nil
    end
  end

  defmodule Chgs do
    alias Electric.DDLX.Command
    alias Electric.Replication.Changes
    alias Electric.Postgres.Extension

    def tx(changes, attrs \\ []) do
      %Changes.Transaction{changes: changes}
      |> put_tx_attrs(attrs)
    end

    def insert(table, record, attrs \\ []) do
      %Changes.NewRecord{relation: table, record: record}
      |> put_change_attrs(attrs)
    end

    def update(table, old_record, changes, attrs \\ []) do
      Changes.UpdatedRecord.new(
        relation: table,
        old_record: old_record,
        record: Map.merge(old_record, changes)
      )
      |> put_change_attrs(attrs)
    end

    def delete(table, record, attrs \\ []) do
      %Changes.DeletedRecord{relation: table, old_record: record}
      |> put_change_attrs(attrs)
    end

    def ddlx(attrs) when is_list(attrs) do
      attrs
      |> Command.ddlx()
      |> ddlx()
    end

    def ddlx(ddlx) do
      bytes = Protox.encode!(ddlx) |> IO.iodata_to_binary()

      %Changes.NewRecord{
        relation: Extension.ddlx_relation(),
        record: %{
          "ddlx" => bytes
        }
      }
    end

    defp put_tx_attrs(tx, attrs) do
      Map.put(tx, :lsn, LSN.new(attrs[:lsn]))
    end

    defp put_change_attrs(change, attrs) do
      tags = Keyword.get(attrs, :tags, [])

      %{change | tags: tags}
    end
  end

  defmodule Roles do
    alias Electric.Satellite.SatPerms, as: P

    def role(role_name, assign_id) do
      %P.Role{role: role_name, assign_id: assign_id}
    end

    def role(role_name, table, id, assign_id, attrs \\ []) do
      struct(
        %P.Role{
          assign_id: assign_id,
          role: role_name,
          user_id: Keyword.get(attrs, :user_id, Auth.user_id()),
          scope: %P.Scope{table: relation(table), id: List.wrap(id)}
        },
        attrs
      )
    end

    defp relation({schema, name}) do
      %P.Table{schema: schema, name: name}
    end
  end

  defmodule Tree do
    @moduledoc """
    Simple implementation of the `Electric.Satellite.Permissions.Graph` behaviour using graphs
    """

    @behaviour Electric.Satellite.Permissions.Graph

    alias Electric.Replication.Changes
    alias Electric.Satellite.Permissions
    alias Electric.Postgres.Schema.FkGraph

    @type vertex() :: {{String.t(), String.t()}, String.t(), [vertex()]}

    @root :__root__

    def new(vs, fk_edges) do
      {__MODULE__, {data_tree(vs), fk_graph(fk_edges)}}
    end

    defp fk_graph(fk_edges) do
      FkGraph.new(fk_edges)
    end

    defp graph(attrs \\ []) do
      Permissions.Graph.graph(attrs)
    end

    def add_vertex({__MODULE__, {graph, fks}}, v) do
      graph = Graph.add_vertex(graph, v)
      {__MODULE__, {graph, fks}}
    end

    def delete_vertex({__MODULE__, {graph, fks}}, v) do
      graph = Graph.delete_vertex(graph, v)
      {__MODULE__, {graph, fks}}
    end

    def add_edge({__MODULE__, {graph, fks}}, a, b) do
      graph = Graph.add_edge(graph, a, b)
      {__MODULE__, {graph, fks}}
    end

    defp data_tree(vs) do
      {_, graph} = Enum.reduce(vs, {@root, graph()}, &build_data_tree/2)

      graph
    end

    defp build_data_tree({table, id, children}, {parent, graph}) when is_list(children) do
      build_data_tree({table, id, %{}, children}, {parent, graph})
    end

    defp build_data_tree({table, id}, {parent, graph}) do
      build_data_tree({table, id, %{}, []}, {parent, graph})
    end

    defp build_data_tree({_table, _id, _attrs, children} = v, {parent, graph}) do
      graph = Graph.add_edge(graph, v(v), v(parent))

      {_v, graph} = Enum.reduce(children, {v, graph}, &build_data_tree/2)
      {parent, graph}
    end

    defp v(@root), do: @root

    defp v({table, id, _attrs, _children}) do
      {table, [id]}
    end

    def scope_id(_state, {_, _} = root, {_, _} = root, id) when is_list(id) do
      [{id, [{root, id}]}]
    end

    def scope_id({graph, fks}, {_, _} = root, {_, _} = relation, id) when is_list(id) do
      graph
      |> Permissions.Graph.traverse_fks(fk_path(fks, root, relation), relation, id)
      |> Enum.flat_map(fn
        {{^root, id}, path} -> [{id, path}]
        _other -> []
      end)
    end

    @impl Electric.Satellite.Permissions.Graph
    def scope_path({graph, fks}, {_, _} = root, {_, _} = relation, id) when is_list(id) do
      graph
      |> Permissions.Graph.traverse_fks(fk_path(fks, root, relation), relation, id)
      |> Enum.flat_map(fn
        [{^root, _id} | _] = path -> [Enum.map(path, fn {relation, id} -> {relation, id, []} end)]
        _other -> []
      end)
    end

    @impl Electric.Satellite.Permissions.Graph
    def modified_fks({_graph, fks} = state, {_, _} = root, %Changes.UpdatedRecord{} = update) do
      %Changes.UpdatedRecord{
        changed_columns: changed_columns,
        old_record: old,
        record: new,
        relation: relation
      } = update

      case FkGraph.foreign_keys(fks, root, relation) do
        [] ->
          []

        foreign_keys ->
          path = FkGraph.path(fks, root, relation)

          foreign_keys
          |> Stream.filter(fn {_fk_relation, fk_cols} ->
            Enum.any?(fk_cols, &MapSet.member?(changed_columns, &1))
          end)
          |> Enum.map(fn {fk_relation, fk_cols} ->
            if fk_relation in path do
              # the change affects this row, that is fk changes pointing "up" the tree (towards
              # `root`)
              {relation, primary_key(state, relation, old), primary_key(state, relation, new)}
            else
              # the change affects a table "down" the tree, away from the `root` we're not
              # checking that the relation is in the scope because it *has* to be if the
              # update relation is
              {fk_relation, Enum.map(fk_cols, &Map.fetch!(old, &1)),
               Enum.map(fk_cols, &Map.fetch!(new, &1))}
            end
          end)
      end
    end

    @impl Electric.Satellite.Permissions.Graph
    def primary_key(_state, _relation, record) do
      [Map.fetch!(record, "id")]
    end

    @impl Electric.Satellite.Permissions.Graph
    def parent({_graph, fks}, {_, _} = root, relation, record) when is_map(record) do
      with [^relation, parent_rel | _] <- FkGraph.path(fks, root, relation),
           [_ | _] = relations <- FkGraph.foreign_keys(fks, root, relation),
           {^parent_rel, fk_cols} <- Enum.find(relations, &match?({^parent_rel, _}, &1)) do
        {parent_rel, Enum.map(fk_cols, &Map.get(record, &1, nil))}
      else
        _ -> nil
      end
    end

    @impl Electric.Satellite.Permissions.Graph
    def apply_change({graph, fks} = state, roots, change) do
      updated =
        Enum.reduce(roots, graph, fn root, graph ->
          case change do
            %Changes.DeletedRecord{relation: relation, old_record: %{"id" => id}} ->
              Graph.delete_vertex(graph, {relation, [id]})

            %Changes.NewRecord{relation: relation, record: %{"id" => id} = record} ->
              case parent(state, root, relation, record) do
                nil ->
                  Graph.add_vertex(graph, {relation, [id]})

                parent ->
                  validate_fk!(graph, parent)

                  Graph.add_edge(graph, {relation, [id]}, parent)
              end

            # we copy the satellite and treat all updates as upserts
            %Changes.UpdatedRecord{} = change ->
              %{relation: relation, old_record: old, record: %{"id" => id} = new} = change

              case modified_fks(state, root, change) do
                [] ->
                  graph

                modified_keys ->
                  child = {relation, [id]}

                  Enum.reduce(modified_keys, graph, fn
                    {^relation, _old_id, _new_id}, graph ->
                      old_parent = parent(state, root, relation, old)
                      new_parent = parent(state, root, relation, new)

                      validate_fk!(graph, new_parent)

                      graph
                      |> Graph.delete_edge(child, old_parent)
                      |> Graph.add_edge(child, new_parent)

                    {fk_relation, old_id, new_id}, graph ->
                      old_parent = {fk_relation, old_id}
                      new_parent = {fk_relation, new_id}
                      validate_fk!(graph, new_parent)

                      graph
                      |> Graph.delete_edge(child, old_parent)
                      |> Graph.add_edge(child, new_parent)
                  end)
              end
          end
        end)

      {updated, fks}
    end

    defp validate_fk!(graph, parent) do
      unless Graph.has_vertex?(graph, parent) do
        raise Permissions.Graph.Error,
          message: "foreign key reference to non-existent record #{inspect(parent)}"
      end
    end

    defp fk_path(_fks, root, root) do
      [root]
    end

    defp fk_path(fks, root, relation) do
      FkGraph.path(fks, root, relation)
    end
  end

  def table({_schema, table}) do
    table
  end

  def perms_build(cxt, grants, roles, attrs \\ []) do
    %{schema_version: schema_version} = cxt

    attrs
    |> Perms.new()
    |> Perms.update(schema_version, grants, roles)
  end

  defmodule Proto do
    alias Electric.DDLX.Command
    alias Electric.Satellite.SatPerms

    def table(schema \\ "public", name) do
      %SatPerms.Table{schema: schema, name: name}
    end

    def scope(schema \\ "public", name) do
      table(schema, name)
    end

    def role(name) do
      %SatPerms.RoleName{role: {:application, name}}
    end

    def authenticated() do
      %SatPerms.RoleName{role: {:predefined, :AUTHENTICATED}}
    end

    def anyone() do
      %SatPerms.RoleName{role: {:predefined, :ANYONE}}
    end

    def assign(attrs) do
      SatPerms.Assign |> struct(attrs) |> Command.put_id()
    end

    def unassign(attrs) do
      SatPerms.Unassign |> struct(attrs) |> Command.put_id()
    end

    def grant(attrs) do
      SatPerms.Grant |> struct(attrs) |> Command.put_id()
    end

    def revoke(attrs) do
      SatPerms.Revoke |> struct(attrs) |> Command.put_id()
    end

    def sqlite(stmt) do
      %SatPerms.Sqlite{stmt: stmt} |> Command.put_id()
    end

    def encode(struct) do
      Protox.encode!(struct) |> IO.iodata_to_binary()
    end
  end

  defmodule Sqlite do
    alias Electric.Postgres.Extension.SchemaLoader

    def build_tree(conn, data) do
      {conn, _} = Enum.reduce(data, {conn, nil}, &build_data_tree/2)
      conn
    end

    defp build_data_tree({table, id, children}, {conn, parent}) when is_list(children) do
      build_data_tree({table, id, %{}, children}, {conn, parent})
    end

    defp build_data_tree({table, id}, {conn, parent}) do
      build_data_tree({table, id, %{}, []}, {conn, parent})
    end

    defp build_data_tree({_table, id, attrs, children} = v, {conn, parent}) do
      init =
        case parent do
          nil ->
            {
              ["id"],
              ["'#{id}'"]
            }

          {_table, _id, _attrs, _children} = parent ->
            {
              ["id", fk(parent)],
              ["'#{id}'", "'#{id(parent)}'"]
            }
        end

      {cols, vals} =
        Enum.reduce(attrs, init, fn {k, v}, {ks, vs} ->
          {[k | ks], ["'#{v}'" | vs]}
        end)

      query = "INSERT INTO #{t(v)} (#{Enum.join(cols, ",")}) VALUES (#{Enum.join(vals, ",")})"

      :ok = Exqlite.Sqlite3.execute(conn, query)

      {conn, _} = Enum.reduce(children, {conn, v}, &build_data_tree/2)
      {conn, parent}
    end

    defp t({{_, table}, _id, _attrs, _children}) do
      table
    end

    defp t({_schema, table}) do
      table
    end

    defp t(%{schema: _schema, name: table}) do
      table
    end

    defp fk({{_, table}, _id, _attrs, _children}) do
      "#{String.trim_trailing(table, "s")}_id"
    end

    defp fk({_, table}) do
      "#{String.trim_trailing(table, "s")}_id"
    end

    # quote name
    defp q(name) when is_binary(name), do: ~s["#{name}"]

    # list of things, mapped using mapper
    defp l(list, mapper) when is_list(list) and is_function(mapper, 1) do
      list |> Enum.map(mapper) |> Enum.join(", ")
    end

    # TODO: this needs to be a real pk col lookup
    # also needs to support compound pks
    defp pk({_, table}), do: "#{table}.id"

    defp id({_table, id, _attrs, _}), do: id

    def get_scope_query(schema, root, root, where_clause, select_clause \\ nil)

    def get_scope_query(_schema, root, root, where_clause, select_clause) do
      [
        "SELECT ",
        select_clause || pk(root),
        " FROM ",
        t(root),
        " WHERE ",
        pk(root),
        " = ",
        where_clause,
        " LIMIT 1"
      ]
      |> IO.iodata_to_binary()
    end

    def get_scope_query(schema, root, table, where_clause, select_clause) do
      fk_graph = SchemaLoader.Version.fk_graph(schema)

      query = [
        "SELECT ",
        select_clause || pk(root),
        " FROM ",
        t(root)
      ]

      joins =
        Graph.get_shortest_path(fk_graph, table, root)
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.map(fn [a, b] ->
          [%{label: fk_columns}] = Graph.edges(fk_graph, a, b)
          {a, b, fk_columns}
          [" LEFT JOIN ", t(a), " ON ", t(a), ".", fk(b), " = ", pk(b)]
        end)

      # |> Enum.reverse()

      where = [
        " WHERE ",
        pk(table),
        " = ",
        where_clause,
        " LIMIT 1"
      ]

      [query, joins, where]
      |> IO.iodata_to_binary()
    end

    def permissions_triggers(perms, schema) do
      Enum.concat([
        [local_roles_table()],
        Stream.map(schema.tables, fn {table, _schema} -> table_triggers(perms, schema, table) end),
        Stream.map(perms.source.rules.assigns, &assign_triggers(&1, perms, schema))
      ])
    end

    @local_roles_table "__electric_local_roles"
    @local_roles_tombstone_table "__electric_local_roles_tombstone"

    def table_triggers(perms, schema, table) do
      Stream.flat_map([:INSERT, :UPDATE, :DELETE], fn action ->
        %{scoped: scoped, unscoped: unscoped} =
          Map.get(perms.roles, {table, action}, %{scoped: [], unscoped: []})

        dbg({table, scoped, unscoped})

        # if we have an unscoped role in our role grant list for this action (on this table)
        # then we have permission (if the column list and the where clause match)
        # TODO: add comments before each when clause giving source
        case_clauses =
          Enum.concat([
            Stream.flat_map(unscoped, &unscoped_trigger_test(&1, perms, schema, table, action)),
            Stream.flat_map(scoped, &scoped_trigger_test(&1, perms, schema, table, action)),
            local_role_test(perms, schema, table, action),
            # fallback that ensures the when case fails
            ["FALSE"]
          ])
          |> Enum.map(&["        WHEN (", &1, ") THEN TRUE"])
          |> Enum.intersperse("\n")

        additional_triggers =
          Enum.concat([
            # Stream.flat_map(
            #   unscoped,
            #   &unscoped_column_limit_trigger(&1, perms, schema, table, action)
            # ),
            scope_move_triggers(scoped, perms, schema, table, action)
          ])

        case_body =
          Enum.intersperse(
            ["    SELECT CASE", case_clauses, "        ELSE FALSE", "    END"],
            "\n"
          )

        [
          IO.iodata_to_binary([
            """
            -----------------------------------------------

            DROP TRIGGER IF EXISTS "#{trigger_name(table, action)}";

            CREATE TRIGGER "#{trigger_name(table, action)}" BEFORE #{action} ON #{t(table)}
            FOR EACH ROW WHEN NOT (
            #{case_body}
            ) BEGIN
                SELECT RAISE(ROLLBACK, 'does not have matching #{action} permissions on "#{t(table)}"');
            END;
            """
          ])
          | additional_triggers
        ]
      end)
      |> Stream.concat(global_triggers(table, schema))
      |> Enum.join("\n")
    end

    defp e(s) when is_binary(s), do: "'#{:binary.replace(s, "'", "''", [:global])}'"
    defp e(n) when is_integer(n) or is_float(n), do: "#{n}"

    defp global_triggers(table, schema) do
      {:ok, pks} = SchemaLoader.Version.primary_keys(schema, table)

      trigger_name = trigger_name(table, :UPDATE, ["protect_pk"])

      column_list =
        pks
        |> Stream.map(&~s["#{&1}"])
        |> Enum.join(", ")

      [
        IO.iodata_to_binary([
          """
          -----------------------------------------------

          DROP TRIGGER IF EXISTS "#{trigger_name}";

          CREATE TRIGGER "#{trigger_name}" BEFORE UPDATE OF #{column_list} ON #{t(table)}
          FOR EACH ROW BEGIN
              SELECT RAISE(ROLLBACK, 'invalid update of primary key on \"#{t(table)}\"');
          END;
          """
        ])
      ]
    end

    defp scope_move_triggers([_ | _] = scoped, _perms, schema, table, :UPDATE) do
      fk_graph = SchemaLoader.Version.fk_graph(schema)

      scopes =
        Enum.flat_map(scoped, fn %{role: %{scope: {scope_table, scope_id}} = _role} ->
          {:ok, pks} = SchemaLoader.Version.primary_keys(schema, table)

          case Graph.get_shortest_path(fk_graph, table, scope_table) do
            nil ->
              []

            [^table, parent] ->
              [%{label: fks}] = Graph.edges(fk_graph, table, parent)

              when_clause =
                IO.iodata_to_binary([
                  "(",
                  scope_id |> Enum.map(&e/1) |> Enum.join(", "),
                  ") = (select ",
                  fks |> Enum.map(&"NEW.#{&1}") |> Enum.join(", "),
                  ")"
                ])

              [{{scope_table, fks}, when_clause}]

            [^table | [parent | _] = _path] ->
              [%{label: fks}] = Graph.edges(fk_graph, table, parent)

              when_clause =
                IO.iodata_to_binary([
                  "(",
                  scope_id |> Enum.map(&e/1) |> Enum.join(", "),
                  ") = (",
                  get_scope_query(
                    schema,
                    scope_table,
                    parent,
                    "NEW.#{hd(fks)}",
                    pks |> Enum.map(&"#{t(scope_table)}.#{&1}") |> Enum.join(", ")
                  ),
                  ")"
                ])

              [{{scope_table, fks}, when_clause}]
          end
        end)
        |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))

      trigger_name = trigger_name(table, :UPDATE, ["scope_move"])

      for {{_scope_root, [fk]}, when_clauses} <- scopes do
        IO.iodata_to_binary([
          """
          -----------------------------------------------

          DROP TRIGGER IF EXISTS "#{trigger_name}";

          CREATE TRIGGER "#{trigger_name}" BEFORE UPDATE OF #{Enum.join([fk], ", ")} ON #{t(table)}
          FOR EACH ROW WHEN NOT (
          SELECT CASE
          #{when_clauses |> Enum.map(&"    WHEN (#{&1}) THEN TRUE") |> Enum.join("\n")}
              ELSE FALSE
          END
          ) BEGIN
              SELECT RAISE(ROLLBACK, 'does not have matching UPDATE permissions in new scope on \"#{t(table)}\"');
          END;
          """
        ])
      end
    end

    defp scope_move_triggers(_scoped, _perms, _schema, _table, _action) do
      []
    end

    defp column_protection(base_test, role_grant, _perms, schema, table, action) do
      case role_grant.grant.columns do
        :all ->
          [base_test]

        allowed_columns ->
          {:ok, table_schema} = SchemaLoader.Version.table(schema, table)

          disallowed_columns =
            table_schema.columns
            |> Stream.map(& &1.name)
            |> Enum.reject(&MapSet.member?(allowed_columns, &1))

          [
            "(",
            base_test,
            ") AND ",
            column_test(disallowed_columns, action),
            ""
          ]
      end
    end

    defp column_test(disallowed_columns, :INSERT) do
      [
        "(",
        disallowed_columns
        |> Enum.map(&"(NEW.#{&1} IS NULL)")
        |> Enum.join(" AND "),
        ")"
      ]
    end

    defp column_test(disallowed_columns, :UPDATE) do
      [
        "(",
        disallowed_columns
        |> Enum.map(&~s[(NEW."#{&1}" IS OLD."#{&1}")])
        |> Enum.join(" AND "),
        ")"
      ]
    end

    # TODO: where clause (for all)
    defp unscoped_trigger_test(role_grant, perms, schema, table, action) do
      # generally when we have an unscoped role for a grant, then we're good
      [column_protection("TRUE", role_grant, perms, schema, table, action)]
    end

    # TODO: where clause (for all)
    defp scoped_trigger_test(role_grant, perms, schema, table, action) do
      %{role: %{scope: {root, scope_id}} = role} = role_grant

      {scope_table, where_clause} =
        case action do
          :INSERT ->
            {parent_table, fk_column} = fk_column(schema, root, table)
            {parent_table, "NEW.#{fk_column}"}

          :UPDATE ->
            {table, "OLD.id"}

          :DELETE ->
            {table, "OLD.id"}
        end

      {:ok, pks} = SchemaLoader.Version.primary_keys(schema, root)

      scope_query = get_scope_query(schema, root, scope_table, where_clause)

      [
        [
          "\n",
          """
              WITH __scope__ AS (#{scope_query}),
                   __tomb__ AS (
                      SELECT t.row_id FROM #{@local_roles_tombstone_table} t
                        WHERE t.assign_id IS #{e(role.assign_id)}
                  )
              SELECT (
          """,
          """
                  (
                      (#{l(scope_id, &e/1)}) = (SELECT #{l(pks, &q/1)} FROM __scope__)
                      AND (#{Jason.encode!(role.id) |> e()} NOT IN (SELECT row_id FROM __tomb__))
                  ) OR (
                      (SELECT json_array(#{l(pks, &q/1)}) FROM __scope__) = (
                          SELECT r.scope_id FROM #{q(@local_roles_table)} r WHERE
                            (r.assign_id IS #{e(role.assign_id)})
                            AND (r.role IS #{e(role_grant.grant.role)})
                            AND (r.row_id NOT IN (SELECT row_id FROM __tomb__))
                      )
                  )
          """
          |> column_protection(role_grant, perms, schema, table, action),
          "    )"
        ]
      ]
    end

    defp local_role_test(perms, schema, table, action) do
      # TODO: have to build triggers based mostly on rules, not on the role-grant structures
      # because I can't update the role-grants when a new role is added, like i do for the ex version
      []
    end

    defp local_roles_table do
      # TODO: clean up local roles and tombstones
      # - local roles can be deleted when updated roles from electric come in and the corresponding (assign_id, row_id) exists in the perms
      # - tombstones can be deleted when updated roles from electric come in and the (assign_id, row_id) no longer exists in the perms
      """
      CREATE TABLE IF NOT EXISTS "#{@local_roles_table}" (
          assign_id TEXT NOT NULL,
          row_id    TEXT NOT NULL,
          scope_id  TEXT,
          role      TEXT NOT NULL,
          PRIMARY KEY (assign_id, row_id)
      );

      CREATE TABLE IF NOT EXISTS "#{@local_roles_tombstone_table}" (
          assign_id TEXT NOT NULL,
          row_id    TEXT NOT NULL,
          PRIMARY KEY (assign_id, row_id)
      );
      """
    end

    defp assign_triggers(assign, perms, schema) when not is_nil(perms.auth.user_id) do
      # FIXME: should only run when user id of membership table = ME
      user_id = perms.auth.user_id

      Enum.map([:INSERT, :UPDATE, :DELETE], fn action ->
        role =
          case assign.role_column do
            nil ->
              assign.role_name

            column ->
              ~s[#{assign_trigger_prefix(action)}."#{column}"]
          end

        body =
          case action do
            :INSERT ->
              [
                """
                    INSERT INTO "#{@local_roles_table}"
                        (assign_id, row_id, scope_id, role)
                    VALUES (
                        #{e(assign.id)},
                        #{assign_row_id(assign, schema, action)},
                        #{assign_scope_id(assign, schema, action)},
                        #{role}
                    );
                """
              ]

            :DELETE ->
              [
                """
                    DELETE FROM "#{@local_roles_table}"
                    WHERE assign_id IS #{e(assign.id)}
                          AND row_id IS #{assign_row_id(assign, schema, action)};
                """,
                """
                    INSERT INTO "#{@local_roles_tombstone_table}"
                        (assign_id, row_id)
                    VALUES (
                        #{e(assign.id)},
                        #{assign_row_id(assign, schema, action)}
                    );
                """
              ]

            :UPDATE ->
              case assign.role_column do
                nil ->
                  []

                column ->
                  [
                    """
                        UPDATE "#{@local_roles_table}"
                        SET role = NEW."#{column}"
                        WHERE assign_id IS #{e(assign.id)}
                              AND row_id IS #{assign_row_id(assign, schema, action)};
                    """
                  ]
              end
          end

        body
        |> Enum.with_index()
        |> Enum.map(fn {stmt, n} ->
          trigger_name = trigger_name(assign.table, action, ["assign", assign.id, "#{n}"])

          """
          -----------------------------------------------

          DROP TRIGGER IF EXISTS "#{trigger_name}";

          CREATE TRIGGER "#{trigger_name}" BEFORE #{action} ON #{t(assign.table)}
          FOR EACH ROW WHEN (
              #{assign_trigger_prefix(action)}."#{assign.user_column}" IS #{e(user_id)}
          ) BEGIN
          #{stmt}
          END;
          """
        end)
      end)
    end

    defp assign_triggers(_assign, _perms, _schema) do
      []
    end

    defp assign_row_id(assign, schema, action) do
      {:ok, pks} =
        SchemaLoader.Version.primary_keys(schema, assign.table.schema, assign.table.name)

      prefix = assign_trigger_prefix(action)

      pk_cols = l(pks, &~s[#{prefix}."#{&1}"])

      ~s[json_array(#{pk_cols})]
    end

    defp assign_scope_id(%{scope: nil} = _assign, _schema, _action) do
      "NULL"
    end

    defp assign_scope_id(assign, schema, action) do
      %{
        table: %{schema: sname, name: tname},
        scope: %{schema: scope_schema, name: scope_table}
      } = assign

      prefix = assign_trigger_prefix(action)

      {_, fk} = fk_column(schema, {scope_schema, scope_table}, {sname, tname})

      fk_cols = l([fk], &~s[#{prefix}."#{&1}"])

      ~s[json_array(#{fk_cols})]
    end

    defp assign_trigger_prefix(action) do
      case action do
        :UPDATE -> "OLD"
        :INSERT -> "NEW"
        :DELETE -> "OLD"
      end
    end

    defp trigger_name(table, action, suffixes \\ []) do
      Enum.join(["__electric_perms_#{t(table)}_#{action}" | suffixes], "_")
    end

    defp fk_column(schema, root, table) do
      fk_graph = SchemaLoader.Version.fk_graph(schema)
      [_, parent | _rest] = Graph.get_shortest_path(fk_graph, table, root)
      {parent, fk(parent)}
    end
  end
end
