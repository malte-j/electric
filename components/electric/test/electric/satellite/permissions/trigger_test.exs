defmodule Electric.Satellite.Permissions.TriggerTest do
  use ExUnit.Case, async: true
  use Electric.Postgres.MockSchemaLoader

  alias Electric.Satellite.Permissions.Trigger
  alias Electric.Satellite.SatPerms

  alias ElectricTest.PermissionsHelpers.{
    Auth,
    Chgs,
    Perms,
    Tree
  }

  import ElectricTest.PermissionsHelpers

  @workspaces {"public", "workspaces"}
  @projects {"public", "projects"}
  @issues {"public", "issues"}
  @comments {"public", "comments"}
  @reactions {"public", "reactions"}
  @project_memberships {"public", "project_memberships"}

  setup do
    loader_spec =
      MockSchemaLoader.backend_spec(
        migrations: [
          {"01",
           [
             "create table users (id uuid primary key)",
             "create table workspaces (id uuid primary key)",
             "create table projects (id uuid primary key, workspace_id uuid not null references workspaces (id))",
             "create table issues (id uuid primary key, project_id uuid not null references projects (id))",
             "create table comments (id uuid primary key, issue_id uuid not null references issues (id))",
             "create table reactions (id uuid primary key, comment_id uuid not null references comments (id))",
             """
             create table project_memberships (
                id uuid primary key,
                user_id uuid not null references users (id),
                project_id uuid not null references projects (id),
                role text not null
             )
             """
             # "create table regions (id uuid primary key)",
             # "create table offices (id uuid primary key, region_id uuid not null references regions (id))",
             # "create table projects (id uuid primary key, workspace_id uuid not null references workspaces (id))",
             # "create table users (id uuid primary key)",
             # "create table teams (id uuid primary key)",
             # """
             # create table team_memberships (
             #    id uuid primary key,
             #    user_id uuid not null references users (id),
             #    team_id uuid not null references teams (id),
             #    team_role text not null
             # )
             # """,
             # """
             # create table site_admins (
             #    id uuid primary key,
             #    user_id uuid not null references users (id),
             #    site_role text not null
             # )
             # """,
             # """
             # create table my_default.admin_users (
             #    id uuid primary key,
             #    user_id uuid not null references users (id)
             # )
             # """
           ]}
        ]
      )

    {:ok, loader} = SchemaLoader.connect(loader_spec, [])
    {:ok, schema_version} = SchemaLoader.load(loader)

    tree =
      Tree.new(
        [
          {@workspaces, "w1",
           [
             {@projects, "p1", []},
             {@projects, "p2", []},
             {@projects, "p3", []}
           ]}
        ],
        [
          {@comments, @issues, ["issue_id"]},
          {@issues, @projects, ["project_id"]},
          {@project_memberships, @projects, ["project_id"]},
          {@projects, @workspaces, ["workspace_id"]},
          {@reactions, @comments, ["comment_id"]}
        ]
      )

    {:ok, _} = start_supervised(Perms.Transient)

    {:ok, tree: tree, loader: loader, schema_version: schema_version}
  end

  def assign(ddlx) do
    %{assigns: [assign | _]} = Perms.to_rules(ddlx)

    assign
  end

  def callback(event, change, :loader) do
    {event, change}
  end

  describe "for_assign/1" do
    test "generates a function that turns inserts into transient roles", cxt do
      assign =
        assign(
          "assign (projects, #{table(@project_memberships)}.role) to #{table(@project_memberships)}.user_id"
        )

      assert {@project_memberships, fun} =
               Trigger.for_assign(assign, cxt.schema_version, &callback/3)

      assert is_function(fun, 2)

      %{id: assign_id} = assign
      user_id = Auth.user_id()

      change =
        Chgs.insert(@project_memberships, %{
          "id" => "pm1",
          "project_id" => "p1",
          "user_id" => user_id,
          "role" => "admin"
        })

      assert {{:insert, role}, ^change} = fun.(change, :loader)

      assert %SatPerms.Role{
               row_id: ["pm1"],
               role: "admin",
               assign_id: ^assign_id,
               user_id: ^user_id,
               scope: %SatPerms.Scope{
                 table: %SatPerms.Table{schema: "public", name: "projects"},
                 id: ["p1"]
               }
             } = role

      # assert [] = fun.(change, cxt.tree, Auth.user("1191723b-37a5-46c8-818e-326cfbc2c0a7"))
      # assert [] = fun.(change, cxt.tree, Auth.nobody())
    end

    test "supports static role names", cxt do
      assign =
        assign("assign (projects, 'something') to #{table(@project_memberships)}.user_id")

      assert {@project_memberships, fun} =
               Trigger.for_assign(assign, cxt.schema_version, &callback/3)

      assert is_function(fun, 2)

      %{id: assign_id} = assign
      user_id = Auth.user_id()

      change =
        Chgs.insert(@project_memberships, %{
          "id" => "pm1",
          "project_id" => "p1",
          "user_id" => user_id
        })

      assert {{:insert, role}, ^change} = fun.(change, :loader)

      assert %SatPerms.Role{
               row_id: ["pm1"],
               role: "something",
               assign_id: ^assign_id,
               user_id: ^user_id,
               scope: %SatPerms.Scope{
                 table: %SatPerms.Table{schema: "public", name: "projects"},
                 id: ["p1"]
               }
             } = role
    end

    test "global role assignments, dynamic roles", cxt do
      assign =
        assign(
          "assign #{table(@project_memberships)}.role to #{table(@project_memberships)}.user_id"
        )

      assert {@project_memberships, fun} =
               Trigger.for_assign(assign, cxt.schema_version, &callback/3)

      assert is_function(fun, 2)

      %{id: assign_id} = assign
      user_id = Auth.user_id()

      change =
        Chgs.insert(@project_memberships, %{
          "id" => "pm1",
          "project_id" => "p1",
          "user_id" => user_id,
          "role" => "admin"
        })

      assert {{:insert, role}, ^change} = fun.(change, :loader)

      assert %SatPerms.Role{
               row_id: ["pm1"],
               role: "admin",
               assign_id: ^assign_id,
               user_id: ^user_id,
               scope: nil
             } = role
    end

    test "global role assignments, static roles", cxt do
      assign =
        assign("assign 'something' to #{table(@project_memberships)}.user_id")

      assert {@project_memberships, fun} =
               Trigger.for_assign(assign, cxt.schema_version, &callback/3)

      assert is_function(fun, 2)

      %{id: assign_id} = assign
      user_id = Auth.user_id()

      change =
        Chgs.insert(@project_memberships, %{
          "id" => "pm1",
          "project_id" => "p1",
          "user_id" => user_id
        })

      assert {{:insert, role}, ^change} = fun.(change, :loader)

      assert %SatPerms.Role{
               row_id: ["pm1"],
               role: "something",
               assign_id: ^assign_id,
               user_id: ^user_id,
               scope: nil
             } = role
    end
  end
end
