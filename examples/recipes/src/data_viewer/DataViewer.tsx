import { Box, Paper } from '@mui/material'
import { useLiveQuery } from 'electric-sql/react'
import { useElectric } from '../electric/ElectricWrapper'
import { useMemo, useState } from 'react'
import { ColumnDef, TableView } from './TableView'
import { columns, aggregateColumns } from './commerce_orders_columns'
import { QueryBuilder } from './QueryBuilder'
import { ChartView } from './ChartView'
import { Selector } from './Selector'
import { PaginationState, SortingState, useTableData } from './use_table_data'

interface PropertyValue {
  property: string
  value: number
}

interface MonthlyPropertyValue extends PropertyValue {
  month: string
}

export const DataViewer = () => {
  // Keep a where clause generated by a query builder
  const [whereClause, setWhereClause] = useState('1 = 1')

  return (
    <Paper sx={{ p: 4 }}>
      <Box sx={{ mb: 2, display: 'flex' }}>
        <Box sx={{ flex: 1, mr: 2 }}>
          <QueryBuilder columns={columns} onQueryChanged={setWhereClause} />
        </Box>
        <Box sx={{ flex: 1 }}>
          <ChartDataViewer aggregateCols={aggregateColumns} whereClause={whereClause} />
        </Box>
      </Box>
      <TableDataViewer columns={columns} whereClause={whereClause} />
    </Paper>
  )
}

const TableDataViewer = ({
  columns,
  whereClause,
}: {
  columns: ColumnDef[]
  whereClause: string
}) => {
  // Keep pagination state to only load necessary data
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: 5,
  })

  // Keep an order by clause generated by the sorting of columns
  const [sorting, setSorting] = useState<SortingState[]>([])

  const { orders, totalNumberOfOrders } = useTableData({ sorting, pagination, whereClause })

  return (
    <TableView
      columns={columns}
      rows={orders}
      totalNumberOfRows={totalNumberOfOrders}
      pagination={pagination}
      onPaginationChange={setPagination}
      sorting={sorting}
      onSortingChange={setSorting}
    />
  )
}

const ChartDataViewer = ({
  whereClause,
  aggregateCols,
}: {
  whereClause: string
  aggregateCols: { field: string; headerName: string }[]
}) => {
  // Specify how many values to show
  const [numValuesToShow] = useState(5)

  // The property by which results will be grouped and aggregated
  const [groupProperty, setGroupProperty] = useState(aggregateCols[0].field)

  const { db } = useElectric()!

  // Find the top values for the given query and select a few to display
  const { results: topValues = [] } = useLiveQuery<PropertyValue[]>(
    db.liveRawQuery({
      sql: `
      SELECT ${groupProperty} as property, COUNT(${groupProperty}) as value
      FROM commerce_orders
      WHERE ${whereClause}
      GROUP BY property
      ORDER BY value DESC
      LIMIT ${numValuesToShow}
    `,
    }),
  )
  const keysToShow = useMemo(
    () => topValues.map((r) => r.property).filter((p) => p !== null),
    [topValues],
  )

  // Get the aggregated number of orders, grouped by the given property, for the top keys
  const { results: aggregatedValues = [] } = useLiveQuery<MonthlyPropertyValue[]>(
    db.liveRawQuery({
      sql: `
      SELECT
        strftime('%Y-%m', timestamp) AS month,
        ${groupProperty} as property,
        COUNT(${groupProperty}) as value
      FROM commerce_orders
      WHERE ${whereClause}
      GROUP BY month, property
      ORDER BY month ASC, value DESC
    `,
    }),
  )

  // Convert to appropriate format to show on the chart
  const dataset = useMemo(
    () =>
      Object.values(
        aggregatedValues.reduce(
          (aggregated, row) => ({
            ...aggregated,
            [row.month]: {
              ...(aggregated[row.month] ?? {
                month: new Date(row.month),
                ...keysToShow.reduce((agg, key) => ({ ...agg, [key]: 0 }), {}),
              }),
              [row.property]: row.value,
            },
          }),
          {} as Record<string, Record<string, number>>,
        ),
      ),
    [aggregatedValues, keysToShow],
  )

  return (
    <Box sx={{ position: 'relative' }}>
      <Selector
        sx={{ position: 'absolute', right: 0, zIndex: 1 }}
        selectedValue={groupProperty}
        values={aggregateCols.map((c) => c.field)}
        valueLabels={aggregateCols.map((c) => c.headerName)}
        label="Aggregate By"
        onValueSelected={setGroupProperty}
      />
      <ChartView
        xAxis={{
          dataKey: 'month',
          scaleType: 'time',
          label: 'Month',
        }}
        yAxis={{
          label: 'Number of Orders',
          tickMinStep: 1,
        }}
        keysToShow={keysToShow}
        dataset={dataset}
        height={400}
      />
    </Box>
  )
}
