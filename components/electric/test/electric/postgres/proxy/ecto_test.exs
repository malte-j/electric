defmodule Electric.Postgres.Proxy.EctoTest do
  use Electric.Proxy.Case, async: false

  alias Electric.Postgres.Extension
  alias Electric.Postgres.Extension.SchemaLoader

  import Electric.Postgres.TestConnection

  @tag ecto: true
  test "migrations", cxt do
    migration_path = Path.expand("../../../support/migrations/proxy/ecto", __DIR__)
    assert File.dir?(migration_path)

    Ecto.Migrator.with_repo(cxt.repo, fn repo ->
      Ecto.Migrator.run(repo, migration_path, :up, all: true)
    end)

    assert {:ok, [r1, r2]} = Extension.ddl_history(cxt.conn)

    assert r1["query"] ==
             "CREATE TABLE table1 (\n    id text NOT NULL,\n    name text,\n    CONSTRAINT table1_pkey PRIMARY KEY (id)\n);\n\n\n"

    assert r2["query"] == "ALTER TABLE \"public\".\"table1\" ADD COLUMN \"value\" text"

    assert {:ok, "20230904162657"} ==
             Extension.tx_version(cxt.conn, r1)

    assert {:ok, "20230905122033"} ==
             Extension.tx_version(cxt.conn, r2)
  end
end
