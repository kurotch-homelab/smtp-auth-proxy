import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '@/api/client'
import {
  Badge,
  Button,
  Card,
  Cell,
  EmptyState,
  ErrorNotice,
  Input,
  Row,
  Spinner,
  Table,
} from '@/components/ui'
import { formatDateTime, formatDetails } from '@/lib/format'

const pageSize = 50

export function AuditPage() {
  const [params, setParams] = useSearchParams()
  const action = params.get('action') ?? ''
  const change = (key: string, value: string) => {
    setParams((current) => {
      const next = new URLSearchParams(current)
      if (value) next.set(key, value)
      else next.delete(key)
      if (key !== 'page') next.delete('page')
      return next
    })
  }
  const setAction = (value: string) => {
    change('action', value)
  }
  const [actionDraft, setActionDraft] = useState(action)
  const page = Math.max(0, Number(params.get('page')) || 0)
  const setPage = (value: number) => {
    change('page', String(value))
  }
  const [expanded, setExpanded] = useState<string | undefined>()

  const query = useQuery({
    queryKey: ['audit', params.toString()],
    queryFn: () =>
      api.audit.list({
        action: action || undefined,
        targetType: params.get('targetType') || undefined,
        targetId: params.get('targetId') || undefined,
        since: params.get('since') || undefined,
        until: params.get('until') || undefined,
        limit: pageSize,
        offset: page * pageSize,
      }),
  })

  const total = query.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <Card
      title="Audit log"
      actions={
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            setPage(0)
            setAction(actionDraft)
          }}
        >
          <Input
            aria-label="Filter by action"
            placeholder="e.g. mailbox.update"
            value={actionDraft}
            onChange={(e) => {
              setActionDraft(e.target.value)
            }}
          />
          <Button type="submit">Filter</Button>
        </form>
      }
    >
      <div className="mb-4 flex flex-wrap gap-2">
        {['targetType', 'targetId'].map((key) => (
          <Input
            key={key}
            aria-label={key}
            placeholder={key === 'targetType' ? 'Target type' : 'Target ID'}
            value={params.get(key) ?? ''}
            onChange={(e) => {
              change(key, e.target.value)
            }}
          />
        ))}
        {['since', 'until'].map((key) => (
          <label key={key}>
            {key === 'since' ? 'From (UTC)' : 'Until (UTC)'}
            <Input
              type="datetime-local"
              value={(params.get(key) ?? '').slice(0, 16)}
              onChange={(e) => {
                change(key, e.target.value ? e.target.value + ':00Z' : '')
              }}
            />
          </label>
        ))}
      </div>
      {query.isLoading ? (
        <Spinner />
      ) : query.error ? (
        <ErrorNotice error={query.error} />
      ) : query.data && query.data.items.length === 0 ? (
        <EmptyState title="Nothing recorded yet">
          {action ? 'No entries match this filter.' : 'Changes appear here as they are made.'}
        </EmptyState>
      ) : (
        <>
          <Table headers={['When', 'Who', 'Action', 'Target', 'Result', '']}>
            {query.data?.items.map((entry) => (
              <Row key={entry.id}>
                <Cell className="whitespace-nowrap">{formatDateTime(entry.at)}</Cell>
                <Cell>
                  {entry.actorName ?? entry.actorType}
                  {entry.ip && <p className="text-xs text-ink-muted">{entry.ip}</p>}
                </Cell>
                <Cell>
                  <code className="text-xs">{entry.action}</code>
                </Cell>
                <Cell>{entry.targetName ?? entry.targetId ?? '—'}</Cell>
                <Cell>
                  {entry.result === 'success' ? (
                    <Badge tone="success">ok</Badge>
                  ) : (
                    <Badge tone="danger">failed</Badge>
                  )}
                </Cell>
                <Cell>
                  {entry.details !== '{}' && (
                    <Button
                      variant="ghost"
                      onClick={() => {
                        setExpanded(expanded === entry.id ? undefined : entry.id)
                      }}
                    >
                      {expanded === entry.id ? 'Hide' : 'Details'}
                    </Button>
                  )}
                  {expanded === entry.id && (
                    <pre className="mt-2 max-w-md overflow-x-auto rounded bg-surface p-2 text-xs">
                      {formatDetails(entry.details)}
                    </pre>
                  )}
                </Cell>
              </Row>
            ))}
          </Table>

          {pages > 1 && (
            <div className="mt-3 flex items-center justify-between text-sm">
              <span className="text-ink-muted">{total} entries</span>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  disabled={page === 0}
                  onClick={() => {
                    setPage(page - 1)
                  }}
                >
                  Previous
                </Button>
                <span>
                  {page + 1} / {pages}
                </span>
                <Button
                  disabled={page + 1 >= pages}
                  onClick={() => {
                    setPage(page + 1)
                  }}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </Card>
  )
}
