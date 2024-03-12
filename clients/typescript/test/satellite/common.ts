import { mkdir, rm as removeFile } from 'node:fs/promises'
import { randomValue } from '../../src/util'
import type { Database as SqliteDB } from 'better-sqlite3'
import SqliteDatabase from 'better-sqlite3'
import { DatabaseAdapter as SqliteDatabaseAdapter } from '../../src/drivers/better-sqlite3'
import { SqliteBundleMigrator, PgBundleMigrator } from '../../src/migrators'
import { EventNotifier, MockNotifier } from '../../src/notifiers'
import { MockSatelliteClient } from '../../src/satellite/mock'
import { GlobalRegistry, Registry, SatelliteProcess } from '../../src/satellite'
import { TableInfo, initTableInfo } from '../support/satellite-helpers'
import { satelliteDefaults, SatelliteOpts } from '../../src/satellite/config'
import { Table, generateTableTriggers } from '../../src/migrators/triggers'
import { buildInitialMigration as makeInitialMigration } from '../../src/migrators/schema'

import sqliteMigrations from '../support/migrations/migrations.js'
import pgMigrations from '../support/migrations/pg-migrations.js'
import { ExecutionContext } from 'ava'
import { AuthState } from '../../src/auth'
import { DbSchema, TableSchema } from '../../src/client/model/schema'
import { PgBasicType } from '../../src/client/conversions/types'
import { HKT } from '../../src/client/util/hkt'
import { ElectricClient } from '../../src/client/model'
import EventEmitter from 'events'
import { QueryBuilder } from '../../src/migrators/query-builder'
import { BundleMigratorBase } from '../../src/migrators/bundle'
import { makePgDatabase } from '../support/node-postgres'
import { DatabaseAdapter as PgDatabaseAdapter } from '../../src/drivers/node-postgres/adapter'
import { DatabaseAdapter } from '../../src/electric/adapter'

export type Database = {
  exec(statement: { sql: string }): Promise<unknown>
}

export function wrapDB(db: SqliteDB): Database {
  const wrappedDB = {
    exec: async ({ sql }: { sql: string }) => {
      console.log('EXECCC:\n' + sql)
      db.exec(sql)
    },
  }
  return wrappedDB
}

export const dbDescription = new DbSchema(
  {
    child: {
      fields: new Map([
        ['id', PgBasicType.PG_INTEGER],
        ['parent', PgBasicType.PG_INTEGER],
      ]),
      relations: [],
    },
    parent: {
      fields: new Map([
        ['id', PgBasicType.PG_INTEGER],
        ['value', PgBasicType.PG_TEXT],
        ['other', PgBasicType.PG_INTEGER],
      ]),
      relations: [],
    },
    another: {
      fields: new Map([['id', PgBasicType.PG_INTEGER]]),
      relations: [],
    },
  } as unknown as Record<
    string,
    TableSchema<any, any, any, any, any, any, any, any, any, HKT>
  >,
  []
)

export const relations = {
  child: {
    id: 0,
    schema: 'public',
    table: 'child',
    tableType: 0,
    columns: [
      {
        name: 'id',
        type: 'INTEGER',
        isNullable: false,
        primaryKey: true,
      },
      {
        name: 'parent',
        type: 'INTEGER',
        isNullable: true,
        primaryKey: false,
      },
    ],
  },
  parent: {
    id: 1,
    schema: 'public',
    table: 'parent',
    tableType: 0,
    columns: [
      {
        name: 'id',
        type: 'INTEGER',
        isNullable: false,
        primaryKey: true,
      },
      {
        name: 'value',
        type: 'TEXT',
        isNullable: true,
        primaryKey: false,
      },
      {
        name: 'other',
        type: 'INTEGER',
        isNullable: true,
        primaryKey: false,
      },
    ],
  },
  another: {
    id: 2,
    schema: 'public',
    table: 'another',
    tableType: 0,
    columns: [
      {
        name: 'id',
        type: 'INTEGER',
        isNullable: false,
        primaryKey: true,
      },
    ],
  },
  mergeTable: {
    id: 3,
    schema: 'public',
    table: 'mergeTable',
    tableType: 0,
    columns: [
      {
        name: 'id',
        type: 'INTEGER',
        isNullable: false,
        primaryKey: true,
      },
      {
        name: 'real',
        type: 'REAL',
        isNullable: true,
        primaryKey: false,
      },
      {
        name: 'int8',
        type: 'INT8',
        isNullable: true,
        primaryKey: false,
      },
      {
        name: 'bigint',
        type: 'BIGINT',
        isNullable: true,
        primaryKey: false,
      },
    ],
  },
  personTable: {
    id: 4,
    schema: 'public',
    table: 'personTable',
    tableType: 0,
    columns: [
      {
        name: 'id',
        type: 'REAL',
        isNullable: false,
        primaryKey: true,
      },
      {
        name: 'name',
        type: 'TEXT',
        isNullable: true,
        primaryKey: false,
      },
      {
        name: 'age',
        type: 'INTEGER',
        isNullable: true,
        primaryKey: false,
      },
      {
        name: 'bmi',
        type: 'REAL',
        isNullable: true,
        primaryKey: false,
      },
      {
        name: 'int8',
        type: 'INT8',
        isNullable: true,
        primaryKey: false,
      },
    ],
  },
  bigIntTable: {
    id: 5,
    schema: 'public',
    table: 'bigIntTable',
    tableType: 0,
    columns: [
      {
        name: 'value',
        type: 'INT8',
        isNullable: false,
        primaryKey: true,
      },
    ],
  },
}

// Speed up the intervals for testing.
export const opts = Object.assign({}, satelliteDefaults, {
  minSnapshotWindow: 40,
  pollingInterval: 200,
})

type Opts = SatelliteOpts & {
  minSnapshotWindow: number
  pollingInterval: number
}

export interface TestNotifier extends EventNotifier {
  notifications: any[]
}

export type ContextType<Extra = {}> = {
  dbName: string
  adapter: DatabaseAdapter
  notifier: TestNotifier
  satellite: SatelliteProcess
  client: MockSatelliteClient
  runMigrations: () => Promise<void>
  tableInfo: TableInfo
  timestamp: number
  authState: AuthState
  token: string
  stop?: () => Promise<void>
} & Extra

const makeContextInternal = async (
  t: ExecutionContext<ContextType>,
  dbName: string,
  adapter: DatabaseAdapter,
  migrator: BundleMigratorBase,
  options: Opts = opts
) => {
  const notifier = new MockNotifier(dbName)
  const client = new MockSatelliteClient()
  const satellite = new SatelliteProcess(
    dbName,
    adapter,
    migrator,
    notifier,
    client,
    options
  )

  const tableInfo = initTableInfo()
  const timestamp = new Date().getTime()

  const runMigrations = async () => {
    await migrator.up()
  }

  const authState = { clientId: '' }
  const token = insecureAuthToken({ sub: 'test-user' })

  t.context = {
    dbName,
    adapter,
    notifier,
    client,
    runMigrations,
    satellite,
    tableInfo,
    timestamp,
    authState,
    token,
  }
}

export const makeContext = async (
  t: ExecutionContext<ContextType>,
  options: Opts = opts
) => {
  await mkdir('.tmp', { recursive: true })
  const dbName = `.tmp/test-${randomValue()}.db`
  const db = new SqliteDatabase(dbName)
  const adapter = new SqliteDatabaseAdapter(db)
  const migrator = new SqliteBundleMigrator(adapter, sqliteMigrations)
  makeContextInternal(t, dbName, adapter, migrator, options)
}

export const makePgContext = async (
  t: ExecutionContext<ContextType>,
  port: number,
  options: Opts = opts
) => {
  const dbName = `test-${randomValue()}`
  const { db, stop } = await makePgDatabase(dbName, port)
  const adapter = new PgDatabaseAdapter(db)
  const migrator = new PgBundleMigrator(adapter, pgMigrations)
  makeContextInternal(t, dbName, adapter, migrator, options)
  t.context.stop = stop
}

export const makeContext = async (
  t: ExecutionContext<ContextType>,
  options: Opts = opts
) => {
  await mkdir('.tmp', { recursive: true })
  const dbName = `.tmp/test-${randomValue()}.db`
  const db = new SqliteDatabase(dbName)
  const adapter = new SqliteDatabaseAdapter(db)
  const migrator = new SqliteBundleMigrator(adapter, sqliteMigrations)
  makeContextInternal(t, dbName, adapter, migrator, options)
}

export const makePgContext = async (
  t: ExecutionContext<ContextType>,
  port: number,
  options: Opts = opts
) => {
  const dbName = `test-${randomValue()}`
  const { db, stop } = await makePgDatabase(dbName, port)
  const adapter = new PgDatabaseAdapter(db)
  const migrator = new PgBundleMigrator(adapter, pgMigrations)
  makeContextInternal(t, dbName, adapter, migrator, options)
  t.context.stop = stop
}

export const mockElectricClient = async (
  db: SqliteDB,
  registry: Registry | GlobalRegistry,
  options: Opts = opts
): Promise<ElectricClient<any>> => {
  const dbName = db.name
  const adapter = new SqliteDatabaseAdapter(db)
  const migrator = new SqliteBundleMigrator(adapter, sqliteMigrations)
  const notifier = new MockNotifier(dbName, new EventEmitter())
  const client = new MockSatelliteClient()
  const satellite = new SatelliteProcess(
    dbName,
    adapter,
    migrator,
    notifier,
    client,
    options
  )

  await satellite.start({ clientId: '' })
  registry.satellites[dbName] = satellite

  // @ts-ignore Mock Electric client that does not contain the DAL
  const electric = new ElectricClient(
    {},
    dbName,
    adapter,
    notifier,
    satellite,
    registry
  )
  await electric.connect(insecureAuthToken({ sub: 'test-token' }))
  return electric
}

export const clean = async (t: ExecutionContext<{ dbName: string }>) => {
  const { dbName } = t.context

  await removeFile(dbName, { force: true })
  await removeFile(`${dbName}-journal`, { force: true })
}

export const cleanAndStopSatellite = async (
  t: ExecutionContext<{
    dbName: string
    satellite: SatelliteProcess
    stop?: () => Promise<void>
  }>
) => {
  const { satellite } = t.context
  await satellite.stop()
  await clean(t)
  await t.context.stop?.()
}

export async function migrateDb(
  db: Database,
  table: Table,
  builder: QueryBuilder
) {
  // First create the "main" schema (only when running on PG)
  const initialMigration = makeInitialMigration(builder)
  const migration = initialMigration.migrations[0].statements
  const [createMainSchema, ...restMigration] = migration
  await db.exec({ sql: createMainSchema })

  const namespace = table.namespace
  const tableName = table.tableName
  // Create the table in the database on the given namespace
  const createTableSQL = `CREATE TABLE "${namespace}"."${tableName}" (id REAL PRIMARY KEY, name TEXT, age INTEGER, bmi REAL, int8 INTEGER)`
  await db.exec({ sql: createTableSQL })

  // Apply the initial migration on the database
  for (const stmt of restMigration) {
    await db.exec({ sql: stmt })
  }

  // Generate the table triggers
  const triggers = generateTableTriggers(table, builder)

  // Apply the triggers on the database
  for (const trigger of triggers) {
    await db.exec({ sql: trigger.sql })
  }
}

export const personTable: Table = {
  namespace: 'main',
  tableName: 'personTable',
  columns: ['id', 'name', 'age', 'bmi', 'int8'],
  primary: ['id'],
  foreignKeys: [],
  columnTypes: {
    id: { sqliteType: 'REAL', pgType: PgBasicType.PG_REAL },
    name: { sqliteType: 'TEXT', pgType: PgBasicType.PG_TEXT },
    age: { sqliteType: 'INTEGER', pgType: PgBasicType.PG_INTEGER },
    bmi: { sqliteType: 'REAL', pgType: PgBasicType.PG_REAL },
    int8: { sqliteType: 'INTEGER', pgType: PgBasicType.PG_INT8 },
  },
}
