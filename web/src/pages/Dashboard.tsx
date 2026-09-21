import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { MessageBar, MessageBarBody } from '@fluentui/react-components'

import { api } from '@/api/client'
import { Badge, Card, ErrorNotice, Spinner, Table, Row, Cell } from '@/components/ui'
import { formatRelative } from '@/lib/format'
import { useSession } from '@/lib/useSession'
import type { MessageStatus } from '@/api/types'

const statusTone: Record<MessageStatus, 'neutral' | 'accent' | 'warning' | 'danger' | 'success'> = {
  queued: 'accent',
  sending: 'accent',
  deferred: 'warning',
  failed: 'danger',
  held: 'neutral',
  sent: 'success',
}

export function DashboardPage() {
  const { can } = useSession()
  const { data, isLoading, error, dataUpdatedAt, isPaused } = useQuery({
    queryKey: ['status'],
    queryFn: () => api.status(),
    // The dashboard answers "is anything broken right now", so it has to be
    // current without the operator reloading.
    refetchInterval: 10_000,
  })

  if (isLoading) return <Spinner />
  if (error && !data) return <ErrorNotice error={error} />
  if (!data) return null

  const failed = data.queueByStatus.failed ?? 0
  const deferred = data.queueByStatus.deferred ?? 0

  return (
    <div className="flex flex-col gap-6">
      {(error || isPaused) && (
        <MessageBar intent="warning">
          <MessageBarBody>
            Live updates are unavailable. Showing the last successful update.
          </MessageBarBody>
        </MessageBar>
      )}
      {failed > 0 || deferred > 0 || data.expiringCredentials.length > 0 ? (
        <Card title="Needs attention">
          {failed > 0 && (
            <div className="app-attention-row">
              <div className="flex items-center gap-3">
                <Badge tone="danger">{failed} failed</Badge>
                <span>Messages need investigation</span>
              </div>
              <Link className="app-text-link" to="/messages?status=failed">
                Review failed messages
              </Link>
            </div>
          )}
          {deferred > 0 && (
            <div className="app-attention-row">
              <Badge tone="warning">{deferred} waiting to retry</Badge>
              <Link to="/messages?status=deferred">Review retrying messages</Link>
            </div>
          )}
          <ul>
            {data.expiringCredentials.map((c) => (
              <li key={c.id} className="app-attention-row">
                <div className="flex flex-wrap items-center gap-3">
                  <Badge tone={c.expiresInDays <= 7 ? 'danger' : 'warning'}>
                    {c.expiresInDays <= 0
                      ? 'expired'
                      : `${String(c.expiresInDays)} day${c.expiresInDays === 1 ? '' : 's'} left`}
                  </Badge>
                  <span>{c.name}</span>
                </div>
                {can('view.config') && (
                  <Link to={`/credentials?id=${c.id}`} className="app-text-link">
                    Review credentials
                  </Link>
                )}
              </li>
            ))}
          </ul>
        </Card>
      ) : (
        !error &&
        !isPaused && (
          <MessageBar intent="success">
            <MessageBarBody>
              No failed or retrying messages, or credentials nearing expiry.
            </MessageBarBody>
          </MessageBar>
        )
      )}

      <div className="grid grid-cols-3 gap-3 sm:gap-4">
        <Stat label="Queued" value={data.queueByStatus.queued ?? 0} />
        <Stat label="Sending" value={data.queueByStatus.sending ?? 0} tone="accent" />
        <Stat label="Deferred" value={data.queueByStatus.deferred ?? 0} />
      </div>

      <Card title="Recent problems">
        {data.recentFailures.length === 0 ? (
          <p className="text-sm text-ink-muted">Nothing is failing right now.</p>
        ) : (
          <Table headers={['Mailbox', 'Recipients', 'Status', 'Reason', 'Received']}>
            {data.recentFailures.map((m) => (
              <Row key={m.id}>
                <Cell>
                  <Link to={`/messages?message=${m.id}`}>
                    {m.mailboxAddress ?? 'Message details'}
                  </Link>
                </Cell>
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

      <div className="flex flex-wrap justify-between gap-2 text-xs text-ink-muted">
        <p>
          {data.mailboxes} mailboxes · {data.accounts} SMTP accounts · {data.credentials}{' '}
          credentials
        </p>
        <p>
          Updated {formatRelative(new Date(dataUpdatedAt).toISOString())} · Version {data.version}
        </p>
      </div>
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
    <div className="app-stat">
      <p>{label}</p>
      <p className={`app-stat-value ${toneClass}`}>{value}</p>
    </div>
  )
}
