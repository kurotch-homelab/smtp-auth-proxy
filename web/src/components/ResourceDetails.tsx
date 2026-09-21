import { MailboxDiagnostics } from './MailboxDiagnostics'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '@/api/client'
import { DetailDrawer } from './DetailDrawer'
import { CopyField } from './CopyField'
import { Button, ErrorNotice, Spinner } from './ui'
import { useSession } from '@/lib/useSession'

export function ResourceDetails({
  kind,
  onEdit,
}: {
  kind: 'accounts' | 'mailboxes' | 'credentials' | 'users'
  onEdit?: (id: string, secret: boolean) => Promise<void>
}) {
  const [params, setParams] = useSearchParams()
  const id = params.get('id') ?? ''
  const { can } = useSession()
  const edit = useMutation({
    mutationFn: async (secret: boolean) => {
      await onEdit?.(id, secret)
    },
  })
  const query = useQuery({
    queryKey: [kind, id],
    queryFn: async () => {
      if (kind === 'users') return { kind, data: await api.users.get(id) } as const
      if (kind === 'accounts') return { kind, data: await api.accounts.get(id) } as const
      if (kind === 'mailboxes') return { kind, data: await api.mailboxes.get(id) } as const
      return { kind, data: await api.credentials.get(id) } as const
    },
    enabled: !!id,
  })
  const mailboxes = useQuery({
    queryKey: ['mailboxes'],
    queryFn: api.mailboxes.list,
    enabled: !!id,
  })
  const accounts = useQuery({
    queryKey: ['accounts'],
    queryFn: api.accounts.list,
    enabled: !!id && kind === 'mailboxes',
  })
  const close = () => {
    setParams((current) => {
      const next = new URLSearchParams(current)
      next.delete('id')
      return next
    })
  }
  if (!id) return null
  const result = query.data
  return (
    <DetailDrawer title="Connection details" onClose={close}>
      {query.error ? (
        <ErrorNotice error={query.error} />
      ) : !result ? (
        <Spinner />
      ) : (
        <div className="resource-details flex flex-col gap-4">
          {result.kind === 'users' && (
            <>
              <h2>{result.data.username}</h2>
              <p>{result.data.displayName}</p>
              <p>{result.data.email}</p>
              <p>Role: {result.data.role}</p>
              <p>
                Sign-in: {result.data.source} · {result.data.disabled ? 'Disabled' : 'Enabled'}
              </p>
            </>
          )}
          {onEdit &&
            can(
              kind === 'accounts'
                ? 'accounts.manage'
                : kind === 'mailboxes'
                  ? 'mailboxes.manage'
                  : kind === 'credentials'
                    ? 'credentials.manage'
                    : 'users.manage',
            ) &&
            (!('managedBy' in result.data) || result.data.managedBy !== 'bootstrap') && (
              <div className="flex gap-2">
                <Button
                  busy={edit.isPending}
                  onClick={() => {
                    edit.mutate(false)
                  }}
                >
                  Edit
                </Button>
                {kind === 'credentials' && (
                  <Button
                    busy={edit.isPending}
                    onClick={() => {
                      edit.mutate(true)
                    }}
                  >
                    Update secret
                  </Button>
                )}
              </div>
            )}
          <ErrorNotice error={edit.error} />
          <CopyField label="ID" value={id} />
          {'managedBy' in result.data && result.data.managedBy === 'bootstrap' && (
            <p>
              Managed in configuration file. Edit the corresponding {kind} entry in the file
              specified by bootstrap.path and restart the service.
            </p>
          )}
          {result.kind === 'accounts' && (
            <>
              <h2>{result.data.username}</h2>
              <p>{result.data.description}</p>
              <p>Sender policy: {result.data.fromPolicy}</p>
              <p>Allowed senders: {result.data.allowedSenders.join(', ') || 'Default policy'}</p>
              <p>
                Network restrictions: {result.data.allowCidrs.join(', ') || 'No CIDR restriction'}
              </p>
              {mailboxes.data?.items
                .filter((m) => result.data.mailboxIds.includes(m.id))
                .map((m) => (
                  <Link key={m.id} to={`/mailboxes?id=${m.id}`}>
                    {m.address}
                  </Link>
                ))}
              <Link to={`/messages?accountId=${id}`}>Related messages</Link>
            </>
          )}
          {result.kind === 'mailboxes' && (
            <>
              <h2>{result.data.address}</h2>
              <p>Transport: {result.data.transport}</p>
              <p>{result.data.enabled ? 'Enabled' : 'Disabled'}</p>
              <Link to={`/credentials?id=${result.data.oauthCredentialId}`}>
                {result.data.credentialName ?? 'Credential details'}
              </Link>
              <p>
                Rate limit: {result.data.rateLimitPerMin ?? 'default'}/min · Concurrent deliveries:{' '}
                {result.data.maxConcurrent ?? 'default'}
              </p>
              {accounts.data?.items
                .filter((a) => a.mailboxIds.includes(id))
                .map((a) => (
                  <Link key={a.id} to={`/accounts?id=${a.id}`}>
                    {a.username}
                  </Link>
                ))}
              <Link to={`/messages?mailboxId=${id}`}>Related messages</Link>
              <MailboxDiagnostics key={id} id={id} />
            </>
          )}
          {result.kind === 'credentials' && (
            <>
              <h2>{result.data.name}</h2>
              <p>Authentication: {result.data.authType}</p>
              <p>Expires: {result.data.expiresAt ?? 'Not recorded'}</p>
              <CopyField label="Tenant ID" value={result.data.tenantId} />
              <CopyField label="Client ID" value={result.data.clientId} />
              <p>Authority: {result.data.authorityHost ?? 'Microsoft default'}</p>
              <h3>Related mailboxes</h3>
              {mailboxes.data?.items
                .filter((m) => m.oauthCredentialId === id)
                .map((m) => (
                  <Link key={m.id} to={`/mailboxes?id=${m.id}`}>
                    {m.address}
                  </Link>
                ))}
            </>
          )}
          <ErrorNotice error={mailboxes.error ?? accounts.error} />
          {can('view.audit') && (
            <Link
              to={`/audit?targetType=${kind === 'accounts' ? 'smtp_account' : kind === 'mailboxes' ? 'mailbox' : kind === 'users' ? 'user' : 'credential'}&targetId=${id}`}
            >
              Audit history
            </Link>
          )}
        </div>
      )}
    </DetailDrawer>
  )
}
