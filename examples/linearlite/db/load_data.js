import createPool, { sql } from '@databases/pg'
import fs from 'fs'
import path from 'path'
import * as url from 'url'
import { v4 as uuidv4 } from 'uuid';

/*
Call with:

ISSUES_TO_LOAD=100 PROJECT_ID=1 PROJECT_NAME='Name' npm run reset
*/

const dirname = url.fileURLToPath(new URL('.', import.meta.url))
const DATABASE_URL =
  process.env.ELECTRIC_DATABASE_URL || process.env.DATABASE_URL
const DATA_DIR = process.env.DATA_DIR || path.resolve(dirname, 'data')
const ISSUES_TO_LOAD = process.env.ISSUES_TO_LOAD || 112
const PROJECT_ID = process.env.PROJECT_ID ?? '1'
const PROJECT_NAME = process.env.PROJECT_NAME ?? 'React'

console.info(`Connecting to Postgres..`)
const db = createPool(DATABASE_URL)

const issues = JSON.parse(
  fs.readFileSync(path.join(DATA_DIR, 'issues.json'), 'utf8')
)

async function makeInsertQuery(db, table, data) {
  const columns = Object.keys(data)
  const columnsNames = columns.join(', ')
  const values = columns.map((column) => data[column])
  return await db.query(sql`
    INSERT INTO ${sql.ident(table)} (${sql(columnsNames)})
    VALUES (${sql.join(values.map(sql.value), ', ')})
  `)
}

async function upsertProject(db, data) {
  const columns = Object.keys(data)
  const columnsNames = columns.join(', ')
  const values = columns.map((column) => data[column])
  return await db.query(sql`
    INSERT INTO project (${sql(columnsNames)})
    VALUES (${sql.join(values.map(sql.value), ', ')})
    ON CONFLICT DO NOTHING
  `)
}

async function importIssue(db, issue) {
  const { comments, ...rest } = issue
  return await makeInsertQuery(db, 'issue', rest)
}

async function importComment(db, comment) {
  return await makeInsertQuery(db, 'comment', comment)
}

// Create the project if it doesn't exist.
upsertProject(db, {
  id: PROJECT_ID,
  name: PROJECT_NAME,
})

let commentCount = 0
const issueToLoad = Math.min(ISSUES_TO_LOAD, issues.length)
await db.tx(async (db) => {
  for (let i = 0; i < issueToLoad; i++) {
    process.stdout.write(`Loading issue ${i + 1} of ${issueToLoad}\r`)
    const issue = issues[i]
    const id = uuidv4()
    await importIssue(db, {
      ...issue,
      id: id,
      project_id: PROJECT_ID,
    })
    for (const comment of issue.comments) {
      commentCount++
      await importComment(db, {
        ...comment,
        issue_id: id,
      })
    }
  }
})
process.stdout.write('\n')

db.dispose()
console.info(`Loaded ${issueToLoad} issues with ${commentCount} comments.`)
