import { useEffect, useState } from 'react'

import { LIB_VERSION } from 'electric-sql/version'
import { makeElectricContext, useLiveQuery } from 'electric-sql/react'
import { genUUID, uniqueTabId } from 'electric-sql/util'
import { ElectricDatabase, electrify } from 'electric-sql/wa-sqlite'

import { authToken } from './auth'
import { Electric, Items as Item, schema } from './generated/client'

import { Tetrominoes as Tetromino, } from './generated/client'
import { tetromino as tetrominoEnum, colour as colourEnum } from './generated/client/prismaClient.d'

import './Example.css'

const angles = [0, 90, 180, 270]

const sample = (array: any[]) => array[Math.floor(Math.random() * array.length)]
const sampleShape = () => sample(Object.keys(tetrominoEnum))
const sampleColour = () => sample(Object.keys(colourEnum))
const sampleAngle = () => sample(angles)

const { ElectricProvider, useElectric } = makeElectricContext<Electric>()

export const Example = () => {
  const [electric, setElectric] = useState<Electric>()

  useEffect(() => {
    let isMounted = true

    const init = async () => {
      const config = {
        auth: {
          token: authToken()
        },
        debug: import.meta.env.DEV,
        url: import.meta.env.ELECTRIC_SERVICE
      }

      const { tabId } = uniqueTabId()
      const scopedDbName = `basic-${LIB_VERSION}-${tabId}.db`

      const conn = await ElectricDatabase.init(scopedDbName)
      const electric = await electrify(conn, schema, config)

      if (!isMounted) {
        return
      }

      setElectric(electric)
    }

    init()

    return () => {
      isMounted = false
    }
  }, [])

  if (electric === undefined) {
    return null
  }

  return (
    <ElectricProvider db={electric}>
      <ExampleComponent />
    </ElectricProvider>
  )
}

const ExampleComponent = () => {
  const { db } = useElectric()!

  useEffect(() => {
    const syncTetrominoes = async () => {
      const shape = await db.tetrominoes.sync()
      await shape.synced
    }

    syncTetrominoes()
  }, [])

  const addPiece = async () => {
    await db.tetrominoes.create({
      data: {
        id: genUUID(),
        shape: sampleShape(),
        colour: sampleColour(),
        angle: sampleAngle()
      }
    })
  }

  const clearPieces = async () => {
    await db.tetrominoes.deleteMany()
  }

  const liveQuery = useLiveQuery(db.tetrominoes.liveMany())
  const pieces: Tetromino[] = liveQuery.results ?? []

  return (
    <div>
      <div className="controls">
        <button className="button" onClick={addPiece}>
          Add
        </button>
        <button className="button" onClick={clearPieces}>
          Clear
        </button>
      </div>
      {pieces.map((piece: Tetromino, index: number) =>
        <p key={index} className="tetromino">
          <code>{piece.id}</code>
          <code>{piece.shape}</code>
          <code>{piece.colour}</code>
          <code>{piece.angle}</code>
        </p>
      )}
    </div>
  )
}
