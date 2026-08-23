import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { api } from '@/api/client'
import { Badge, Card, ErrorNotice, Spinner, Table, Row, Cell } from '@/components/ui'
import { formatRelative } from '@/lib/format'
import type { MessageStatus } from '@/api/types'

/** The statuses worth showing, in the order a queue moves through them. */
const queueOrder: MessageStatus[] = ['queued', 'sending', 'deferred', 'failed', 'held', 'sent']

const statusTone: Record<MessageStatus, 'neutral' | 'accent' | 'warning' | 'danger' | 'success'> = {
  queued: 'accent',
  sending: 'accent',
  deferred: 'warning',
  failed: 'danger',
  held: 'neutral',
  sent: 'success',
}

export function DashboardPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['status'],
    queryFn: () => api.status(),
    // The dashboard answers "is anything broken right now", so it has to be
    // current without the operator reloading.
    refetchInterval: 10_000,
  })

  if (isLoading) return <Spinner />
  if (error) return <ErrorNotice error={error} />
  if (!data) return null

  const waiting = (data.queueByStatus.queued ?? 0) + (data.queueByStatus.deferred ?? 0)
  const failed = data.queueByStatus.failed ?? 0

  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Waiting to send" value={waiting} tone={waiting > 0 ? 'accent' : 'neutral'} />
        <Stat label="Failed" value={failed} tone={failed > 0 ? 'danger' : 'neutral'} />
        <Stat label="Mailboxes" value={data.mailboxes} />
        <Stat label="SMTP accounts" value={data.accounts} />
      </div>

      {data.expiringCredentials.length > 0 && (
        <Card title="Credentials expiring soon">
          {/* A client secret quietly expiring is the most common way a working
              deployment stops working. */}
          <ul className="flex flex-col gap-2 text-sm">
            {data.expiringCredentials.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center gap-2">
                <Badge tone={c.expiresInDays <= 7 ? 'danger' : 'warning'}>
                  {c.expiresInDays <= 0
                    ? 'expired'
                    : `${String(c.expiresInDays)} day${c.expiresInDays === 1 ? '' : 's'} left`}
                </Badge>
                <Link to="/credentials" className="underline">
                  {c.name}
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Queue">
        <div className="flex flex-wrap gap-3">
          {queueOrder.map((status) => (
            <Link
              key={status}
              to={`/queue?status=${status}`}
              className="rounded-md border border-border px-3 py-2 text-sm hover:bg-border/40"
            >
              <span className="mr-2 font-medium">{data.queueByStatus[status] ?? 0}</span>
              <Badge tone={statusTone[status]}>{status}</Badge>
            </Link>
          ))}
        </div>
      </Card>

      <Card title="Recent problems">
        {data.recentFailures.length === 0 ? (
          <p className="text-sm text-ink-muted">Nothing is failing right now.</p>
        ) : (
          <Table headers={['Mailbox', 'Recipients', 'Status', 'Reason', 'Received']}>
            {data.recentFailures.map((m) => (
              <Row key={m.id}>
                <Cell>{m.mailboxAddress ?? '—'}</Cell>
                <Cell>{m.recipients.join(', ')}</Cell>
                <Cell>
                  <Badge tone={statusTone[m.status]}>{m.status}</Badge>
                </Cell>
                <Cell className="max-w-md">
                  {m.lastErrorCode && <code className="mr-1 text-xs">{m.lastErrorCode}</code>}
                  <span className="text-ink-muted">{m.lastError}</span>
                </Cell>
                <Cell className="whitespace-nowrap">{formatRelative(m.receivedAt)}</Cell>
              </Row>
            ))}
          </Table>
        )}
      </Card>

      <p className="text-xs text-ink-muted">Version {data.version}</p>
    </div>
  )
}

function Stat({
  label,
  value,
  tone = 'neutral',
}: {
  label: string
  value: number
  tone?: 'neutral' | 'accent' | 'danger'
}) {
  const toneClass =
    tone === 'danger' ? 'text-danger' : tone === 'accent' ? 'text-accent' : 'text-ink'
  return (
    <div className="rounded-lg border border-border bg-surface-raised p-4">
      <p className="text-xs uppercase tracking-wide text-ink-muted">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${toneClass}`}>{value}</p>
    </div>
  )
}
