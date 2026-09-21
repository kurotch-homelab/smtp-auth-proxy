import { useConfirm } from '@/components/Confirm'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'

import { api } from '@/api/client'
import { DetailDrawer } from '@/components/DetailDrawer'
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
import type { MessageStatus } from '@/api/types'

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
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [params, setParams] = useSearchParams()

  const status = params.get('status') ?? ''
  const search = params.get('search') ?? ''
  const page = Math.max(0, Number(params.get('page')) || 0)
  function change(key: string, value: string) {
    setParams((current) => {
      const next = new URLSearchParams(current)
      if (value) next.set(key, value)
      else next.delete(key)
      if (key !== 'page' && key !== 'message') next.delete('page')
      return next
    })
  }
  const setPage = (value: number) => {
    change('page', String(value))
  }
  const selectedId = params.get('message') ?? ''
  const detail = useQuery({
    queryKey: ['message', selectedId],
    queryFn: () => api.messages.get(selectedId),
    enabled: !!selectedId,
    refetchInterval: 10_000,
  })
  const selected = detail.error ? undefined : detail.data
  const mailboxes = useQuery({ queryKey: ['mailboxes'], queryFn: api.mailboxes.list })
  const accounts = useQuery({ queryKey: ['accounts'], queryFn: api.accounts.list })

  const query = useQuery({
    queryKey: [
      'messages',
      params.getAll('status').join(','),
      search,
      page,
      params.get('mailboxId'),
      params.get('accountId'),
      params.get('since'),
      params.get('until'),
    ],
    queryFn: () =>
      api.messages.list({
        status: params.getAll('status').length ? params.getAll('status') : undefined,
        mailboxId: params.get('mailboxId') || undefined,
        accountId: params.get('accountId') || undefined,
        since: params.get('since') || undefined,
        until: params.get('until') || undefined,
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
      change('message', '')
      await queryClient.invalidateQueries({ queryKey: ['messages'] })
      await queryClient.invalidateQueries({ queryKey: ['status'] })
    },
  })

  const total = query.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="flex flex-col gap-4">
      {query.isPaused && (
        <ErrorNotice
          error={new Error('Live updates are paused. Reconnect to refresh message status.')}
        />
      )}
      {query.dataUpdatedAt > 0 && (
        <p className="text-xs text-ink-muted">
          Last updated {formatDateTime(new Date(query.dataUpdatedAt).toISOString())}
        </p>
      )}
      <div className="flex flex-wrap gap-2" aria-label="Message views">
        {[
          ['Needs attention', 'failed,deferred'],
          ['Processing', 'queued,sending'],
          ['Held', 'held'],
          ['Sent', 'sent'],
          ['All', ''],
        ].map(([label, values]) => (
          <Button
            key={label}
            variant={params.getAll('status').join(',') === values ? 'primary' : 'secondary'}
            aria-pressed={params.getAll('status').join(',') === values}
            onClick={() => {
              setParams((current) => {
                const next = new URLSearchParams(current)
                next.delete('status')
                next.delete('page')
                ;(values ?? '')
                  .split(',')
                  .filter(Boolean)
                  .forEach((v) => {
                    next.append('status', v)
                  })
                return next
              })
            }}
          >
            {label}
          </Button>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <Select
          aria-label="Mailbox"
          value={params.get('mailboxId') ?? ''}
          onChange={(e) => {
            change('mailboxId', e.target.value)
          }}
        >
          <option value="">All mailboxes</option>
          {mailboxes.data?.items.map((m) => (
            <option key={m.id} value={m.id}>
              {m.address}
            </option>
          ))}
        </Select>
        <Select
          aria-label="SMTP account"
          value={params.get('accountId') ?? ''}
          onChange={(e) => {
            change('accountId', e.target.value)
          }}
        >
          <option value="">All SMTP accounts</option>
          {accounts.data?.items.map((a) => (
            <option key={a.id} value={a.id}>
              {a.username}
            </option>
          ))}
        </Select>
        {(['since', 'until'] as const).map((key) => (
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
      <ErrorNotice error={mailboxes.error ?? accounts.error} />
      <Card
        title="Messages"
        actions={
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(event) => {
              event.preventDefault()
              const input = new FormData(event.currentTarget).get('search')
              const searchDraft = typeof input === 'string' ? input : ''
              setParams((current) => {
                const next = new URLSearchParams(current)
                next.delete('page')
                if (searchDraft) next.set('search', searchDraft)
                else next.delete('search')
                return next
              })
            }}
          >
            <Select
              aria-label="Filter by status"
              value={
                params.getAll('status').length > 1 || status.includes(',') ? 'grouped' : status
              }
              onChange={(e) => {
                setParams((current) => {
                  const next = new URLSearchParams(current)
                  next.delete('page')
                  if (e.target.value) next.set('status', e.target.value)
                  else next.delete('status')
                  return next
                })
              }}
            >
              <option value="">All statuses</option>
              <option value="grouped" disabled>
                Selected view
              </option>
              {statuses.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </Select>

            <Input
              aria-label="Search by sender or recipient"
              placeholder="Sender or recipient"
              key={search}
              defaultValue={search}
              name="search"
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
                        change('message', m.id)
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

      {selectedId && !selected && (
        <DetailDrawer
          title="Message details"
          onClose={() => {
            change('message', '')
          }}
        >
          {detail.error ? <ErrorNotice error={detail.error} /> : <Spinner />}
        </DetailDrawer>
      )}
      {selected && (
        <DetailDrawer
          title={`Message ${selected.id}`}
          onClose={() => {
            change('message', '')
          }}
          actions={
            <div className="flex flex-wrap gap-2">
              {can('queue.manage') && (
                <>
                  <Button
                    disabled={!['failed', 'deferred', 'held'].includes(selected.status)}
                    busy={act.isPending}
                    onClick={() => {
                      act.mutate({ id: selected.id, action: 'retry' })
                    }}
                  >
                    Send now
                  </Button>
                  <Button
                    disabled={!['queued', 'deferred', 'failed'].includes(selected.status)}
                    busy={act.isPending}
                    onClick={() => {
                      act.mutate({ id: selected.id, action: 'hold' })
                    }}
                  >
                    Hold
                  </Button>
                  <Button
                    variant="danger"
                    disabled={selected.status === 'sending'}
                    busy={act.isPending}
                    onClick={() => {
                      void (async () => {
                        if (
                          await confirm(
                            selected.status === 'sent'
                              ? 'Delete history and body? This cannot be undone.'
                              : 'Discard this message? It cannot be recovered.',
                          )
                        ) {
                          act.mutate({ id: selected.id, action: 'delete' })
                        }
                      })()
                    }}
                  >
                    {selected.status === 'sent' ? 'Delete history and body' : 'Discard'}
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
                  change('message', '')
                }}
              >
                Close
              </Button>
            </div>
          }
        >
          <ErrorNotice error={act.error} />
          <div className="mb-4 flex flex-wrap gap-3">
            {selected.mailboxId && (
              <Link to={`/mailboxes?id=${selected.mailboxId}`}>Mailbox details</Link>
            )}
            {selected.smtpAccountId && (
              <Link to={`/accounts?id=${selected.smtpAccountId}`}>SMTP account details</Link>
            )}
          </div>
          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
            <Detail
              label="Submission"
              value={selected.origin === 'diagnostic' ? 'Diagnostic test' : 'SMTP submission'}
            />
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
              <Detail label="Accepted by Microsoft 365" value={formatDateTime(selected.sentAt)} />
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
        </DetailDrawer>
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
