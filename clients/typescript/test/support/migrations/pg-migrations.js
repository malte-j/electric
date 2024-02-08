/*
  Autogenerated ElectricSQL config file. Don't edit this
  file directly. Instead, use the `electric` CLI tool
  to manage your config and migrations.

  See https://electric-sql.com/docs for more information.
*/

export default [
  {
    statements: [
      'DROP TABLE IF EXISTS main._electric_trigger_settings;',
      'CREATE TABLE main._electric_trigger_settings(namespace TEXT, tablename TEXT, flag INTEGER, PRIMARY KEY (namespace, tablename));',
    ],
    version: '1',
  },
  {
    statements: [
      'CREATE TABLE IF NOT EXISTS main.items (\n  value TEXT PRIMARY KEY NOT NULL\n);',
      'CREATE TABLE IF NOT EXISTS main.parent (\n  id INTEGER PRIMARY KEY NOT NULL,\n  value TEXT,\n  other INTEGER DEFAULT 0\n);',
      'CREATE TABLE IF NOT EXISTS main.child (\n  id INTEGER PRIMARY KEY NOT NULL,\n  parent INTEGER NOT NULL,\n  FOREIGN KEY(parent) REFERENCES main.parent(id)\n);',
      'DROP TABLE IF EXISTS main._electric_trigger_settings;',
      'CREATE TABLE main._electric_trigger_settings(namespace TEXT, tablename TEXT, flag INTEGER, PRIMARY KEY (namespace, tablename));',
      "INSERT INTO main._electric_trigger_settings(namespace, tablename,flag) VALUES ('main', 'child', 1);",
      "INSERT INTO main._electric_trigger_settings(namespace, tablename,flag) VALUES ('main', 'items', 1);",
      "INSERT INTO main._electric_trigger_settings(namespace, tablename,flag) VALUES ('main', 'parent', 1);",

      'DROP TRIGGER IF EXISTS update_ensure_main_child_primarykey ON main.child;',
      `
      CREATE OR REPLACE FUNCTION update_ensure_main_child_primarykey_function()
      RETURNS TRIGGER AS $$
      BEGIN
        IF old.id != new.id THEN
          RAISE EXCEPTION 'cannot change the value of column id as it belongs to the primary key';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;`,
      `
      CREATE TRIGGER update_ensure_main_child_primarykey
      BEFORE UPDATE ON main.child
      FOR EACH ROW
      EXECUTE FUNCTION update_ensure_main_child_primarykey_function();
      `,

      'DROP TRIGGER IF EXISTS insert_main_child_into_oplog ON main.child',

      `
      CREATE OR REPLACE FUNCTION insert_main_child_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'child';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES ('main', 'child', 'INSERT', jsonb_build_object('id', NEW.id), jsonb_build_object('id', NEW.id, 'parent', NEW.parent), NULL, NULL);
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,

      `
      CREATE TRIGGER insert_main_child_into_oplog
      AFTER INSERT ON main.child
      FOR EACH ROW
      EXECUTE FUNCTION insert_main_child_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS update_main_child_into_oplog ON main.child;',
      `
      CREATE OR REPLACE FUNCTION update_main_child_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'child';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES ('main', 'child', 'UPDATE', jsonb_build_object('id', NEW.id), jsonb_build_object('id', NEW.id, 'parent', NEW.parent), jsonb_build_object('id', OLD.id, 'parent', OLD.parent), NULL);
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,
      `
      CREATE TRIGGER update_main_child_into_oplog
      AFTER UPDATE ON main.child
      FOR EACH ROW
      EXECUTE FUNCTION update_main_child_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS delete_main_child_into_oplog ON main.child;',
      `
      CREATE OR REPLACE FUNCTION delete_main_child_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'child';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES ('main', 'child', 'DELETE', jsonb_build_object('id', OLD.id), NULL, jsonb_build_object('id', OLD.id, 'parent', OLD.parent), NULL);
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,
      `
      CREATE TRIGGER delete_main_child_into_oplog
      AFTER DELETE ON main.child
      FOR EACH ROW
      EXECUTE FUNCTION delete_main_child_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS compensation_insert_main_child_parent_into_oplog ON main.child;',
      `
      CREATE OR REPLACE FUNCTION compensation_insert_main_child_parent_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
          meta_value TEXT;
        BEGIN
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent';

          SELECT value INTO meta_value FROM main._electric_meta WHERE key = 'compensations';

          IF flag_value = 1 AND meta_value = '1' THEN
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            SELECT 'main', 'parent', 'INSERT', jsonb_build_object('id', id),
              jsonb_build_object('id', id, 'value', value, 'other', other), NULL, NULL
            FROM main.parent WHERE id = NEW."parent";
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,
      `
      CREATE TRIGGER compensation_insert_main_child_parent_into_oplog
      AFTER INSERT ON main.child
      FOR EACH ROW
      EXECUTE FUNCTION compensation_insert_main_child_parent_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS compensation_update_main_child_parent_into_oplog ON main.parent;',
      `
      CREATE OR REPLACE FUNCTION compensation_update_main_child_parent_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
          meta_value TEXT;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent';

          -- Get the 'compensations' value from _electric_meta
          SELECT value INTO meta_value FROM main._electric_meta WHERE key = 'compensations';

          IF flag_value = 1 AND meta_value = '1' THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            SELECT 'main', 'parent', 'UPDATE', jsonb_build_object('id', id),
              jsonb_build_object('id', id, 'value', value, 'other', other), NULL, NULL
            FROM main.parent WHERE id = NEW."parent";
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,
      `
      CREATE TRIGGER compensation_update_main_child_parent_into_oplog
      AFTER UPDATE ON main.parent
      FOR EACH ROW
      EXECUTE FUNCTION compensation_update_main_child_parent_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS update_ensure_main_items_primarykey ON main.items;',
      `
      CREATE OR REPLACE FUNCTION update_ensure_main_items_primarykey_function()
      RETURNS TRIGGER AS $$
      BEGIN
        IF old.value != new.value THEN
          RAISE EXCEPTION 'cannot change the value of column value as it belongs to the primary key';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;`,
      `
      CREATE TRIGGER update_ensure_main_items_primarykey
      BEFORE UPDATE ON main.items
      FOR EACH ROW
      EXECUTE FUNCTION update_ensure_main_items_primarykey_function();
      `,

      'DROP TRIGGER IF EXISTS insert_main_items_into_oplog ON main.items;',
      `
      CREATE OR REPLACE FUNCTION insert_main_items_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'items';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES ('main', 'items', 'INSERT', jsonb_build_object('value', NEW.value), jsonb_build_object('value', NEW.value), NULL, NULL);
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,

      `
      -- Attach the trigger function to the table
      CREATE TRIGGER insert_main_items_into_oplog
      AFTER INSERT ON main.items
      FOR EACH ROW
      EXECUTE FUNCTION insert_main_items_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS update_main_items_into_oplog ON main.items;',
      `
      CREATE OR REPLACE FUNCTION update_main_items_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'items';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES ('main', 'items', 'UPDATE', jsonb_build_object('value', NEW.value), jsonb_build_object('value', NEW.value), jsonb_build_object('value', OLD.value), NULL);
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;`,

      `
      -- Attach the trigger function to the table
      CREATE TRIGGER update_main_items_into_oplog
      AFTER UPDATE ON main.items
      FOR EACH ROW
      EXECUTE FUNCTION update_main_items_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS delete_main_items_into_oplog ON main.items;',
      `
      CREATE OR REPLACE FUNCTION delete_main_items_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'items';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES ('main', 'items', 'DELETE', jsonb_build_object('value', OLD.value), NULL, jsonb_build_object('value', OLD.value), NULL);
          END IF;

          RETURN OLD;
        END;
      END;
      $$ LANGUAGE plpgsql;`,
      `
      -- Attach the trigger function to the table
      CREATE TRIGGER delete_main_items_into_oplog
      AFTER DELETE ON main.items
      FOR EACH ROW
      EXECUTE FUNCTION delete_main_items_into_oplog_function();
      `,
      'DROP TRIGGER IF EXISTS update_ensure_main_parent_primarykey ON main.parent;',

      `
      CREATE OR REPLACE FUNCTION update_ensure_main_parent_primarykey_function()
      RETURNS TRIGGER AS $$
      BEGIN
        IF OLD.id != NEW.id THEN
          RAISE EXCEPTION 'cannot change the value of column id as it belongs to the primary key';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
      `,

      `
      -- Attach the trigger function to the table
      CREATE TRIGGER update_ensure_main_parent_primarykey
      BEFORE UPDATE ON main.parent
      FOR EACH ROW
      EXECUTE FUNCTION update_ensure_main_parent_primarykey_function();
      `,

      'DROP TRIGGER IF EXISTS insert_main_parent_into_oplog ON main.parent;',
      `
      CREATE OR REPLACE FUNCTION insert_main_parent_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES (
              'main',
              'parent',
              'INSERT',
              jsonb_build_object('id', NEW.id),
              jsonb_build_object('id', NEW.id, 'value', NEW.value, 'other', NEW.other),
              NULL,
              NULL
            );
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,

      `
      -- Attach the trigger function to the table
      CREATE TRIGGER insert_main_parent_into_oplog
      AFTER INSERT ON main.parent
      FOR EACH ROW
      EXECUTE FUNCTION insert_main_parent_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS update_main_parent_into_oplog ON main.parent;',

      `
      CREATE OR REPLACE FUNCTION update_main_parent_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES (
              'main',
              'parent',
              'UPDATE',
              jsonb_build_object('id', NEW.id),
              jsonb_build_object('id', NEW.id, 'value', NEW.value, 'other', NEW.other),
              jsonb_build_object('id', OLD.id, 'value', OLD.value, 'other', OLD.other),
              NULL
            );
          END IF;

          RETURN NEW;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,

      `
      -- Attach the trigger function to the table
      CREATE TRIGGER update_main_parent_into_oplog
      AFTER UPDATE ON main.parent
      FOR EACH ROW
      EXECUTE FUNCTION update_main_parent_into_oplog_function();
      `,

      'DROP TRIGGER IF EXISTS delete_main_parent_into_oplog ON main.parent;',

      `
      CREATE OR REPLACE FUNCTION delete_main_parent_into_oplog_function()
      RETURNS TRIGGER AS $$
      BEGIN
        DECLARE
          flag_value INTEGER;
        BEGIN
          -- Get the flag value from _electric_trigger_settings
          SELECT flag INTO flag_value FROM main._electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent';

          IF flag_value = 1 THEN
            -- Insert into _electric_oplog
            INSERT INTO main._electric_oplog (namespace, tablename, optype, "primaryKey", "newRow", "oldRow", timestamp)
            VALUES (
              'main',
              'parent',
              'DELETE',
              jsonb_build_object('id', OLD.id),
              NULL,
              jsonb_build_object('id', OLD.id, 'value', OLD.value, 'other', OLD.other),
              NULL
            );
          END IF;

          RETURN OLD;
        END;
      END;
      $$ LANGUAGE plpgsql;
      `,

      `
      -- Attach the trigger function to the table
      CREATE TRIGGER delete_main_parent_into_oplog
      AFTER DELETE ON main.parent
      FOR EACH ROW
      EXECUTE FUNCTION delete_main_parent_into_oplog_function();
      `,
    ],
    version: '2',
  },
]
