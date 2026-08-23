import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

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
  Select,
  Spinner,
  Table,
} from '@/components/ui'
import { formatBytes, formatDateTime, formatRelative } from '@/lib/format'
import { useSession } from '@/lib/useSession'
import type { Message, MessageStatus } from '@/api/types'

const statuses: MessageStatus[] = ['queued', 'sending', 'deferred', 'failed', 'held', 'sent']

const statusTone: Record<MessageStatus, 'neutral' | 'accent' | 'warning' | 'danger' | 'success'> = {
  queued: 'accent',
  sending: 'accent',
  deferred: 'warning',
  failed: 'danger',
  held: 'neutral',
  sent: 'success',
}

const pageSize = 50

export function QueuePage() {
  const { can } = useSession()
  const queryClient = useQueryClient()
  const [params, setParams] = useSearchParams()

  const status = params.get('status') ?? ''
  const search = params.get('search') ?? ''
  const [searchDraft, setSearchDraft] = useState(search)
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<Message | undefined>()

  const query = useQuery({
    queryKey: ['messages', status, search, page],
    queryFn: () =>
      api.messages.list({
        status: status || undefined,
        search: search || undefined,
        limit: pageSize,
        offset: page * pageSize,
      }),
    // A queue that is moving should be seen to move.
    refetchInterval: 10_000,
  })

  const act = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'retry' | 'hold' | 'delete' }) => {
      if (action === 'retry') return api.messages.retry(id)
      if (action === 'hold') return api.messages.hold(id)
      return api.messages.remove(id)
    },
    onSuccess: async () => {
      setSelected(undefined)
      await queryClient.invalidateQueries({ queryKey: ['messages'] })
      await queryClient.invalidateQueries({ queryKey: ['status'] })
    },
  })

  const total = query.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="flex flex-col gap-4">
      <Card
        title="Queue"
        actions={
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(event) => {
              event.preventDefault()
              setPage(0)
              setParams((current) => {
                const next = new URLSearchParams(current)
                if (searchDraft) next.set('search', searchDraft)
                else next.delete('search')
                return next
              })
            }}
          >
            <Select
              aria-label="Filter by status"
              value={status}
              onChange={(e) => {
                setPage(0)
                setParams((current) => {
                  const next = new URLSearchParams(current)
                  if (e.target.value) next.set('status', e.target.value)
                  else next.delete('status')
                  return next
                })
              }}
            >
              <option value="">All statuses</option>
              {statuses.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>

            <Input
              aria-label="Search by sender or recipient"
              placeholder="Sender or recipient"
              value={searchDraft}
              onChange={(e) => {
                setSearchDraft(e.target.value)
              }}
            />
            <Button type="submit">Search</Button>
          </form>
        }
      >
        {query.isLoading ? (
          <Spinner />
        ) : query.error ? (
          <ErrorNotice error={query.error} />
        ) : query.data && query.data.items.length === 0 ? (
          <EmptyState title="Nothing here">
            {status || search
              ? 'No messages match this filter.'
              : 'Messages appear here as devices submit them.'}
          </EmptyState>
        ) : (
          <>
            <ErrorNotice error={act.error} className="mb-3" />
            <Table
              headers={['Status', 'Mailbox', 'From', 'Recipients', 'Received', 'Attempts', '']}
            >
              {query.data?.items.map((m) => (
                <Row key={m.id}>
                  <Cell>
                    <Badge tone={statusTone[m.status]}>{m.status}</Badge>
                  </Cell>
                  <Cell>{m.mailboxAddress ?? '—'}</Cell>
                  <Cell>{m.headerFrom ?? m.envelopeFrom}</Cell>
                  <Cell>
                    {m.recipients.slice(0, 2).join(', ')}
                    {m.recipientCount > 2 && ` +${String(m.recipientCount - 2)}`}
                  </Cell>
                  <Cell className="whitespace-nowrap">{formatRelative(m.receivedAt)}</Cell>
                  <Cell>{m.attempts}</Cell>
                  <Cell>
                    <Button
                      variant="ghost"
                      onClick={() => {
                        setSelected(m)
                      }}
                    >
                      Details
                    </Button>
                  </Cell>
                </Row>
              ))}
            </Table>

            {pages > 1 && (
              <div className="mt-3 flex items-center justify-between text-sm">
                <span className="text-ink-muted">
                  {total} message{total === 1 ? '' : 's'}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    disabled={page === 0}
                    onClick={() => {
                      setPage((p) => p - 1)
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
                      setPage((p) => p + 1)
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

      {selected && (
        <Card
          title={`Message ${selected.id}`}
          actions={
            <div className="flex flex-wrap gap-2">
              {can('queue.manage') && (
                <>
                  <Button
                    busy={act.isPending}
                    onClick={() => {
                      act.mutate({ id: selected.id, action: 'retry' })
                    }}
                  >
                    Send now
                  </Button>
                  <Button
                    busy={act.isPending}
                    onClick={() => {
                      act.mutate({ id: selected.id, action: 'hold' })
                    }}
                  >
                    Hold
                  </Button>
                  <Button
                    variant="danger"
                    busy={act.isPending}
                    onClick={() => {
                      if (confirm('Discard this message? It cannot be recovered.')) {
                        act.mutate({ id: selected.id, action: 'delete' })
                      }
                    }}
                  >
                    Discard
                  </Button>
                </>
              )}
              {/* Downloading the message means reading somebody's mail, so only
                  an administrator is offered it. */}
              {can('queue.read_body') && (
                <a
                  href={api.messages.bodyUrl(selected.id)}
                  className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-border/40"
                >
                  Download
                </a>
              )}
              <Button
                variant="ghost"
                onClick={() => {
                  setSelected(undefined)
                }}
              >
                Close
              </Button>
            </div>
          }
        >
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <Detail label="Status" value={selected.status} />
            <Detail label="Submitted by" value={selected.accountUsername ?? '—'} />
            <Detail label="Sent as" value={selected.mailboxAddress ?? '—'} />
            <Detail label="Envelope sender" value={selected.envelopeFrom} />
            <Detail label="From header" value={selected.headerFrom ?? '—'} />
            <Detail label="Recipients" value={selected.recipients.join(', ')} />
            <Detail label="Size" value={formatBytes(selected.sizeBytes)} />
            <Detail label="Client address" value={selected.clientIp ?? '—'} />
            <Detail label="Received" value={formatDateTime(selected.receivedAt)} />
            <Detail label="Attempts" value={String(selected.attempts)} />
            {selected.nextAttemptAt && (
              <Detail label="Next attempt" value={formatRelative(selected.nextAttemptAt)} />
            )}
            {selected.sentAt && (
              <Detail label="Delivered" value={formatDateTime(selected.sentAt)} />
            )}
          </dl>

          {selected.lastError && (
            <div className="mt-4">
              <p className="text-xs uppercase tracking-wide text-ink-muted">Last error</p>
              <p className="mt-1 text-sm">
                {selected.lastErrorCode && <code className="mr-2">{selected.lastErrorCode}</code>}
                {selected.lastError}
              </p>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-ink-muted">{label}</dt>
      <dd className="break-words">{value}</dd>
    </div>
  )
}
