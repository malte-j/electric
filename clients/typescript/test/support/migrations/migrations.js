/*
  Autogenerated ElectricSQL config file. Don't edit this
  file directly. Instead, use the `electric` CLI tool
  to manage your config and migrations.

  See https://electric-sql.com/docs for more information.
*/

export default [
  {
    statements: [
      'DROP TABLE IF EXISTS _electric_trigger_settings;',
      'CREATE TABLE _electric_trigger_settings(namespace TEXT, tablename TEXT, flag INTEGER, PRIMARY KEY (namespace, tablename));',
    ],
    version: '1',
  },
  {
    statements: [
      'CREATE TABLE IF NOT EXISTS items (\n  value TEXT PRIMARY KEY NOT NULL\n) WITHOUT ROWID;',
      'CREATE TABLE IF NOT EXISTS bigIntTable (\n  value INT8 PRIMARY KEY NOT NULL\n) WITHOUT ROWID;',
      'CREATE TABLE IF NOT EXISTS parent (\n  id INTEGER PRIMARY KEY NOT NULL,\n  value TEXT,\n  other INTEGER DEFAULT 0\n) WITHOUT ROWID;',
      'CREATE TABLE IF NOT EXISTS child (\n  id INTEGER PRIMARY KEY NOT NULL,\n  parent INTEGER NOT NULL,\n  FOREIGN KEY(parent) REFERENCES parent(id)\n) WITHOUT ROWID;',
      'DROP TABLE IF EXISTS _electric_trigger_settings;',
      'CREATE TABLE _electric_trigger_settings(namespace TEXT, tablename TEXT, flag INTEGER, PRIMARY KEY (namespace, tablename));',
      "INSERT INTO _electric_trigger_settings(namespace,tablename,flag) VALUES ('main', 'child', 1);",
      "INSERT INTO _electric_trigger_settings(namespace,tablename,flag) VALUES ('main', 'items', 1);",
      "INSERT INTO _electric_trigger_settings(namespace,tablename,flag) VALUES ('main', 'bigIntTable', 1);",
      "INSERT INTO _electric_trigger_settings(namespace,tablename,flag) VALUES ('main', 'parent', 1);",
      'DROP TRIGGER IF EXISTS update_ensure_main_child_primarykey;',
      "CREATE TRIGGER update_ensure_main_child_primarykey\n   BEFORE UPDATE ON main.child\nBEGIN\n  SELECT\n    CASE\n      WHEN old.id != new.id THEN\n        RAISE (ABORT,'cannot change the value of column id as it belongs to the primary key')\n    END;\nEND;",
      'DROP TRIGGER IF EXISTS insert_main_child_into_oplog;',
      "CREATE TRIGGER insert_main_child_into_oplog\n   AFTER INSERT ON main.child\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'child')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'child', 'INSERT', json_object('id', new.id), json_object('id', new.id, 'parent', new.parent), NULL, NULL);\nEND;",
      'DROP TRIGGER IF EXISTS update_main_child_into_oplog;',
      "CREATE TRIGGER update_main_child_into_oplog\n   AFTER UPDATE ON main.child\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'child')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'child', 'UPDATE', json_object('id', new.id), json_object('id', new.id, 'parent', new.parent), json_object('id', old.id, 'parent', old.parent), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS delete_main_child_into_oplog;',
      "CREATE TRIGGER delete_main_child_into_oplog\n   AFTER DELETE ON main.child\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'child')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'child', 'DELETE', json_object('id', old.id), NULL, json_object('id', old.id, 'parent', old.parent), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS compensation_insert_main_child_parent_into_oplog;',
      "CREATE TRIGGER compensation_insert_main_child_parent_into_oplog\n   AFTER INSERT ON main.child\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent') AND\n        1 == (SELECT value from _electric_meta WHERE key == 'compensations')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  SELECT 'main', 'parent', 'UPDATE', json_object('id', id), json_object('id', id, 'value', value, 'other', other), NULL, NULL\n  FROM main.parent WHERE id = new.parent;\nEND;",
      'DROP TRIGGER IF EXISTS compensation_update_main_child_parent_into_oplog;',
      "CREATE TRIGGER compensation_update_main_child_parent_into_oplog\n   AFTER UPDATE ON main.child\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent') AND\n        1 == (SELECT value from _electric_meta WHERE key == 'compensations')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  SELECT 'main', 'parent', 'UPDATE', json_object('id', id), json_object('id', id, 'value', value, 'other', other), NULL, NULL\n  FROM main.parent WHERE id = new.parent;\nEND;",
      'DROP TRIGGER IF EXISTS update_ensure_main_items_primarykey;',
      "CREATE TRIGGER update_ensure_main_items_primarykey\n   BEFORE UPDATE ON main.items\nBEGIN\n  SELECT\n    CASE\n      WHEN old.value != new.value THEN\n        RAISE (ABORT,'cannot change the value of column value as it belongs to the primary key')\n    END;\nEND;",
      'DROP TRIGGER IF EXISTS insert_main_items_into_oplog;',
      "CREATE TRIGGER insert_main_items_into_oplog\n   AFTER INSERT ON main.items\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'items')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'items', 'INSERT', json_object('value', new.value), json_object('value', new.value), NULL, NULL);\nEND;",
      'DROP TRIGGER IF EXISTS update_main_items_into_oplog;',
      "CREATE TRIGGER update_main_items_into_oplog\n   AFTER UPDATE ON main.items\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'items')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'items', 'UPDATE', json_object('value', new.value), json_object('value', new.value), json_object('value', old.value), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS delete_main_items_into_oplog;',
      "CREATE TRIGGER delete_main_items_into_oplog\n   AFTER DELETE ON main.items\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'items')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'items', 'DELETE', json_object('value', old.value), NULL, json_object('value', old.value), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS update_ensure_main_bigIntTable_primarykey;',
      "CREATE TRIGGER update_ensure_main_bigIntTable_primarykey\n   BEFORE UPDATE ON main.bigIntTable\nBEGIN\n  SELECT\n    CASE\n      WHEN old.value != new.value THEN\n        RAISE (ABORT,'cannot change the value of column value as it belongs to the primary key')\n    END;\nEND;",
      'DROP TRIGGER IF EXISTS insert_main_bigIntTable_into_oplog;',
      "CREATE TRIGGER insert_main_bigIntTable_into_oplog\n   AFTER INSERT ON main.bigIntTable\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'bigIntTable')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'bigIntTable', 'INSERT', json_object('value', new.value), json_object('value', new.value), NULL, NULL);\nEND;",
      'DROP TRIGGER IF EXISTS update_main_bigIntTable_into_oplog;',
      "CREATE TRIGGER update_main_bigIntTable_into_oplog\n   AFTER UPDATE ON main.bigIntTable\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'bigIntTable')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'bigIntTable', 'UPDATE', json_object('value', new.value), json_object('value', new.value), json_object('value', old.value), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS delete_main_bigIntTable_into_oplog;',
      "CREATE TRIGGER delete_main_bigIntTable_into_oplog\n   AFTER DELETE ON main.bigIntTable\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'bigIntTable')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'bigIntTable', 'DELETE', json_object('value', old.value), NULL, json_object('value', old.value), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS update_ensure_main_parent_primarykey;',
      "CREATE TRIGGER update_ensure_main_parent_primarykey\n   BEFORE UPDATE ON main.parent\nBEGIN\n  SELECT\n    CASE\n      WHEN old.id != new.id THEN\n        RAISE (ABORT,'cannot change the value of column id as it belongs to the primary key')\n    END;\nEND;",
      'DROP TRIGGER IF EXISTS insert_main_parent_into_oplog;',
      "CREATE TRIGGER insert_main_parent_into_oplog\n   AFTER INSERT ON main.parent\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'parent', 'INSERT', json_object('id', new.id), json_object('id', new.id, 'value', new.value, 'other', new.other), NULL, NULL);\nEND;",
      'DROP TRIGGER IF EXISTS update_main_parent_into_oplog;',
      "CREATE TRIGGER update_main_parent_into_oplog\n   AFTER UPDATE ON main.parent\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'parent', 'UPDATE', json_object('id', new.id), json_object('id', new.id, 'value', new.value, 'other', new.other), json_object('id', old.id, 'value', old.value, 'other', old.other), NULL);\nEND;",
      'DROP TRIGGER IF EXISTS delete_main_parent_into_oplog;',
      "CREATE TRIGGER delete_main_parent_into_oplog\n   AFTER DELETE ON main.parent\n   WHEN 1 == (SELECT flag from _electric_trigger_settings WHERE namespace = 'main' AND tablename = 'parent')\nBEGIN\n  INSERT INTO _electric_oplog (namespace, tablename, optype, primaryKey, newRow, oldRow, timestamp)\n  VALUES ('main', 'parent', 'DELETE', json_object('id', old.id), NULL, json_object('id', old.id, 'value', old.value, 'other', old.other), NULL);\nEND;",
    ],
    version: '2',
  },
]
