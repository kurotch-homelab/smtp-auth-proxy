import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { ApiError, api } from '@/api/client'
import { CopyField } from '@/components/CopyField'
import { Modal } from '@/components/Modal'
import {
  Badge,
  Button,
  Card,
  Cell,
  EmptyState,
  ErrorNotice,
  Field,
  Input,
  Row,
  Select,
  Spinner,
  Table,
} from '@/components/ui'
import { formatRelative } from '@/lib/format'
import { useSession } from '@/lib/useSession'
import type { Account, FromPolicy } from '@/api/types'

interface AccountForm {
  username: string
  description: string
  defaultMailboxId: string
  mailboxIds: string[]
  allowedSenders: string
  fromPolicy: FromPolicy
  allowCidrs: string
}

const emptyForm: AccountForm = {
  username: '',
  description: '',
  defaultMailboxId: '',
  mailboxIds: [],
  allowedSenders: '',
  fromPolicy: 'reject',
  allowCidrs: '',
}

/** Splits a comma- or newline-separated list the way people actually type it. */
function splitList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function AccountsPage() {
  const { can } = useSession()
  const queryClient = useQueryClient()

  const accounts = useQuery({ queryKey: ['accounts'], queryFn: () => api.accounts.list() })
  const mailboxes = useQuery({ queryKey: ['mailboxes'], queryFn: () => api.mailboxes.list() })

  const [editing, setEditing] = useState<Account | 'new' | undefined>()
  const [form, setForm] = useState<AccountForm>(emptyForm)
  const [password, setPassword] = useState<{ username: string; value: string } | undefined>()

  const save = useMutation({
    mutationFn: (input: { id?: string; body: unknown }) =>
      input.id ? api.accounts.update(input.id, input.body) : api.accounts.create(input.body),
    onSuccess: async (result) => {
      setEditing(undefined)
      // A brand-new account comes back with its generated password, which is
      // the only time it exists outside the operator's hands.
      if ('password' in result && typeof result.password === 'string' && result.password !== '') {
        setPassword({ username: result.username, value: result.password })
      }
      await queryClient.invalidateQueries({ queryKey: ['accounts'] })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.accounts.remove(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['accounts'] })
    },
  })

  const resetPassword = useMutation({
    mutationFn: async (account: Account) => {
      const result = await api.accounts.resetPassword(account.id)
      return { username: account.username, value: result.password }
    },
    onSuccess: (result) => {
      setPassword(result)
    },
  })

  const fieldErrors = save.error instanceof ApiError ? save.error.fields : {}

  const openEditor = (account: Account | 'new') => {
    save.reset()
    setEditing(account)
    if (account === 'new') {
      setForm(emptyForm)
      return
    }
    setForm({
      username: account.username,
      description: account.description ?? '',
      defaultMailboxId: account.defaultMailboxId ?? '',
      mailboxIds: account.mailboxIds,
      allowedSenders: account.allowedSenders.join('\n'),
      fromPolicy: account.fromPolicy,
      allowCidrs: account.allowCidrs.join('\n'),
    })
  }

  const submit = () => {
    const body = {
      username: form.username,
      description: form.description,
      defaultMailboxId: form.defaultMailboxId || null,
      mailboxIds: form.mailboxIds,
      allowedSenders: splitList(form.allowedSenders),
      fromPolicy: form.fromPolicy,
      allowCidrs: splitList(form.allowCidrs),
    }
    save.mutate({ id: editing === 'new' ? undefined : editing?.id, body })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card
        title="SMTP accounts"
        actions={
          can('accounts.manage') && (
            <Button
              variant="primary"
              onClick={() => {
                openEditor('new')
              }}
            >
              New account
            </Button>
          )
        }
      >
        <p className="mb-4 text-sm text-ink-muted">
          Each device or service gets its own username and password. Revoking one never touches the
          others.
        </p>

        {accounts.isLoading ? (
          <Spinner />
        ) : accounts.error ? (
          <ErrorNotice error={accounts.error} />
        ) : accounts.data && accounts.data.items.length === 0 ? (
          <EmptyState title="No accounts yet">
            Create one per device — the printer, the NAS, the monitoring host — so each can be
            revoked on its own.
          </EmptyState>
        ) : (
          <>
            <ErrorNotice error={remove.error} className="mb-3" />
            <Table headers={['Username', 'Sends as', 'Sender policy', 'Last used', 'State', '']}>
              {accounts.data?.items.map((a) => (
                <Row key={a.id}>
                  <Cell>
                    <span className="font-medium">{a.username}</span>
                    {a.description && <p className="text-xs text-ink-muted">{a.description}</p>}
                  </Cell>
                  <Cell>{a.mailboxAddresses.join(', ') || '—'}</Cell>
                  <Cell>
                    <Badge>{a.fromPolicy}</Badge>
                  </Cell>
                  <Cell className="whitespace-nowrap">{formatRelative(a.lastUsedAt)}</Cell>
                  <Cell>
                    {a.enabled ? <Badge tone="success">enabled</Badge> : <Badge>disabled</Badge>}
                    {a.managedBy === 'bootstrap' && <Badge tone="accent">bootstrap</Badge>}
                  </Cell>
                  <Cell>
                    {can('accounts.manage') && a.managedBy !== 'bootstrap' && (
                      <div className="flex flex-wrap gap-1">
                        <Button
                          variant="ghost"
                          onClick={() => {
                            openEditor(a)
                          }}
                        >
                          Edit
                        </Button>
                        <Button
                          variant="ghost"
                          busy={resetPassword.isPending}
                          onClick={() => {
                            if (
                              confirm(
                                `Reset the password for ${a.username}? The device stops working until it is reconfigured.`,
                              )
                            ) {
                              resetPassword.mutate(a)
                            }
                          }}
                        >
                          Reset password
                        </Button>
                        <Button
                          variant="ghost"
                          onClick={() => {
                            save.mutate({ id: a.id, body: { enabled: !a.enabled } })
                          }}
                        >
                          {a.enabled ? 'Disable' : 'Enable'}
                        </Button>
                        <Button
                          variant="ghost"
                          onClick={() => {
                            if (confirm(`Delete ${a.username}? This cannot be undone.`)) {
                              remove.mutate(a.id)
                            }
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    )}
                  </Cell>
                </Row>
              ))}
            </Table>
          </>
        )}
      </Card>

      <Modal
        title={editing === 'new' ? 'New SMTP account' : `Edit ${form.username}`}
        open={editing !== undefined}
        onClose={() => {
          setEditing(undefined)
        }}
      >
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            submit()
          }}
        >
          <Field label="Username" htmlFor="acct-username" error={fieldErrors.username}>
            <Input
              id="acct-username"
              required
              value={form.username}
              onChange={(e) => {
                setForm({ ...form, username: e.target.value })
              }}
            />
          </Field>

          <Field
            label="Description"
            htmlFor="acct-description"
            hint="What device or service uses this."
          >
            <Input
              id="acct-description"
              value={form.description}
              onChange={(e) => {
                setForm({ ...form, description: e.target.value })
              }}
            />
          </Field>

          <Field
            label="Mailboxes this account may send as"
            error={fieldErrors.mailboxIds}
            hint="The From address picks between them; the default is used when nothing matches."
          >
            <div className="flex flex-col gap-1">
              {mailboxes.data?.items.map((mb) => (
                <label key={mb.id} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={form.mailboxIds.includes(mb.id)}
                    onChange={(e) => {
                      setForm({
                        ...form,
                        mailboxIds: e.target.checked
                          ? [...form.mailboxIds, mb.id]
                          : form.mailboxIds.filter((id) => id !== mb.id),
                      })
                    }}
                  />
                  {mb.address}
                </label>
              ))}
              {mailboxes.data?.items.length === 0 && (
                <p className="text-xs text-ink-muted">Create a mailbox first.</p>
              )}
            </div>
          </Field>

          <Field
            label="Default mailbox"
            htmlFor="acct-default"
            error={fieldErrors.defaultMailboxId}
          >
            <Select
              id="acct-default"
              value={form.defaultMailboxId}
              onChange={(e) => {
                setForm({ ...form, defaultMailboxId: e.target.value })
              }}
            >
              <option value="">First linked mailbox</option>
              {mailboxes.data?.items
                .filter((mb) => form.mailboxIds.includes(mb.id))
                .map((mb) => (
                  <option key={mb.id} value={mb.id}>
                    {mb.address}
                  </option>
                ))}
            </Select>
          </Field>

          <Field
            label="Sender policy"
            htmlFor="acct-policy"
            error={fieldErrors.fromPolicy}
            hint="What happens when the From header is not an address this account may use."
          >
            <Select
              id="acct-policy"
              value={form.fromPolicy}
              onChange={(e) => {
                setForm({ ...form, fromPolicy: e.target.value as FromPolicy })
              }}
            >
              <option value="reject">Reject the message</option>
              <option value="rewrite">Rewrite From to the mailbox</option>
              <option value="passthrough">Send it unchanged</option>
            </Select>
          </Field>

          <Field
            label="Additional allowed senders"
            htmlFor="acct-senders"
            error={fieldErrors.allowedSenders}
            hint="One per line: an exact address, or *@example.com for a whole domain."
          >
            <textarea
              id="acct-senders"
              rows={3}
              className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm"
              value={form.allowedSenders}
              onChange={(e) => {
                setForm({ ...form, allowedSenders: e.target.value })
              }}
            />
          </Field>

          <Field
            label="Allowed networks"
            htmlFor="acct-cidrs"
            error={fieldErrors.allowCidrs}
            hint="One CIDR per line, e.g. 10.0.0.0/8. Empty allows any source address."
          >
            <textarea
              id="acct-cidrs"
              rows={2}
              className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm"
              value={form.allowCidrs}
              onChange={(e) => {
                setForm({ ...form, allowCidrs: e.target.value })
              }}
            />
          </Field>

          <ErrorNotice error={save.error} />

          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setEditing(undefined)
              }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" busy={save.isPending}>
              {editing === 'new' ? 'Create' : 'Save'}
            </Button>
          </div>
        </form>
      </Modal>

      <Modal
        title={`Password for ${password?.username ?? ''}`}
        open={password !== undefined}
        onClose={() => {
          setPassword(undefined)
        }}
      >
        <div className="flex flex-col gap-3">
          <p className="text-sm">
            Configure the device with this password now.{' '}
            <strong>It is shown this once and cannot be displayed again.</strong>
          </p>
          {password && <CopyField value={password.value} />}
          <div className="flex justify-end">
            <Button
              variant="primary"
              onClick={() => {
                setPassword(undefined)
              }}
            >
              I have stored it
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
