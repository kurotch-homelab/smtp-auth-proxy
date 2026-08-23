import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { ApiError, api } from '@/api/client'
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
import { useSession } from '@/lib/useSession'
import type { ConnectionTest, Mailbox, Transport } from '@/api/types'

interface MailboxForm {
  address: string
  displayName: string
  oauthCredentialId: string
  transport: Transport
  rateLimitPerMin: string
  maxConcurrent: string
}

const emptyForm: MailboxForm = {
  address: '',
  displayName: '',
  oauthCredentialId: '',
  transport: 'smtp',
  rateLimitPerMin: '',
  maxConcurrent: '',
}

export function MailboxesPage() {
  const { can } = useSession()
  const queryClient = useQueryClient()

  const mailboxes = useQuery({ queryKey: ['mailboxes'], queryFn: () => api.mailboxes.list() })
  const credentials = useQuery({ queryKey: ['credentials'], queryFn: () => api.credentials.list() })

  const [editing, setEditing] = useState<Mailbox | 'new' | undefined>()
  const [form, setForm] = useState<MailboxForm>(emptyForm)
  const [testResult, setTestResult] = useState<
    { mailbox: string; result: ConnectionTest } | undefined
  >()

  const save = useMutation({
    mutationFn: (input: { id?: string; body: unknown }) =>
      input.id ? api.mailboxes.update(input.id, input.body) : api.mailboxes.create(input.body),
    onSuccess: async () => {
      setEditing(undefined)
      await queryClient.invalidateQueries({ queryKey: ['mailboxes'] })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.mailboxes.remove(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['mailboxes'] })
    },
  })

  const test = useMutation({
    mutationFn: async (mailbox: Mailbox) => ({
      mailbox: mailbox.address,
      result: await api.mailboxes.test(mailbox.id),
    }),
    onSuccess: setTestResult,
  })

  const fieldErrors = save.error instanceof ApiError ? save.error.fields : {}

  const openEditor = (mailbox: Mailbox | 'new') => {
    save.reset()
    setEditing(mailbox)
    if (mailbox === 'new') {
      setForm(emptyForm)
      return
    }
    setForm({
      address: mailbox.address,
      displayName: mailbox.displayName ?? '',
      oauthCredentialId: mailbox.oauthCredentialId,
      transport: mailbox.transport,
      rateLimitPerMin: mailbox.rateLimitPerMin?.toString() ?? '',
      maxConcurrent: mailbox.maxConcurrent?.toString() ?? '',
    })
  }

  const submit = () => {
    const body: Record<string, unknown> = {
      address: form.address,
      displayName: form.displayName,
      oauthCredentialId: form.oauthCredentialId,
      transport: form.transport,
    }
    if (form.rateLimitPerMin !== '') body.rateLimitPerMin = Number(form.rateLimitPerMin)
    if (form.maxConcurrent !== '') body.maxConcurrent = Number(form.maxConcurrent)
    save.mutate({ id: editing === 'new' ? undefined : editing?.id, body })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card
        title="Shared mailboxes"
        actions={
          can('mailboxes.manage') && (
            <Button
              variant="primary"
              onClick={() => {
                openEditor('new')
              }}
            >
              New mailbox
            </Button>
          )
        }
      >
        <p className="mb-4 text-sm text-ink-muted">
          Each mailbox is an Exchange Online shared mailbox the proxy may send as. One credential
          can serve many mailboxes.
        </p>

        {mailboxes.isLoading ? (
          <Spinner />
        ) : mailboxes.error ? (
          <ErrorNotice error={mailboxes.error} />
        ) : mailboxes.data && mailboxes.data.items.length === 0 ? (
          <EmptyState title="No mailboxes yet">
            Add a credential first, then the shared mailboxes it may send as.
          </EmptyState>
        ) : (
          <>
            <ErrorNotice error={remove.error} className="mb-3" />
            <ErrorNotice error={test.error} className="mb-3" />
            <Table headers={['Address', 'Credential', 'Transport', 'Limits', 'State', '']}>
              {mailboxes.data?.items.map((mb) => (
                <Row key={mb.id}>
                  <Cell>
                    <span className="font-medium">{mb.address}</span>
                    {mb.displayName && <p className="text-xs text-ink-muted">{mb.displayName}</p>}
                  </Cell>
                  <Cell>{mb.credentialName ?? '—'}</Cell>
                  <Cell>
                    <Badge tone="accent">{mb.transport}</Badge>
                  </Cell>
                  <Cell className="text-xs text-ink-muted">
                    {mb.rateLimitPerMin ?? 'default'}/min · {mb.maxConcurrent ?? 'default'} conc.
                  </Cell>
                  <Cell>
                    {mb.enabled ? <Badge tone="success">enabled</Badge> : <Badge>disabled</Badge>}
                    {mb.managedBy === 'bootstrap' && <Badge tone="accent">bootstrap</Badge>}
                  </Cell>
                  <Cell>
                    <div className="flex flex-wrap gap-1">
                      {can('mailboxes.manage') && (
                        <Button
                          variant="ghost"
                          busy={test.isPending}
                          onClick={() => {
                            test.mutate(mb)
                          }}
                        >
                          Test
                        </Button>
                      )}
                      {can('mailboxes.manage') && mb.managedBy !== 'bootstrap' && (
                        <>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              openEditor(mb)
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              save.mutate({ id: mb.id, body: { enabled: !mb.enabled } })
                            }}
                          >
                            {mb.enabled ? 'Disable' : 'Enable'}
                          </Button>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              if (confirm(`Delete ${mb.address}?`)) {
                                remove.mutate(mb.id)
                              }
                            }}
                          >
                            Delete
                          </Button>
                        </>
                      )}
                    </div>
                  </Cell>
                </Row>
              ))}
            </Table>
          </>
        )}
      </Card>

      <Modal
        title={editing === 'new' ? 'New mailbox' : `Edit ${form.address}`}
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
          <Field
            label="Address"
            htmlFor="mb-address"
            error={fieldErrors.address}
            hint="The shared mailbox's SMTP address; it is also the identity used to authenticate."
          >
            <Input
              id="mb-address"
              type="email"
              required
              value={form.address}
              onChange={(e) => {
                setForm({ ...form, address: e.target.value })
              }}
            />
          </Field>

          <Field label="Display name" htmlFor="mb-name">
            <Input
              id="mb-name"
              value={form.displayName}
              onChange={(e) => {
                setForm({ ...form, displayName: e.target.value })
              }}
            />
          </Field>

          <Field label="Credential" htmlFor="mb-credential" error={fieldErrors.oauthCredentialId}>
            <Select
              id="mb-credential"
              required
              value={form.oauthCredentialId}
              onChange={(e) => {
                setForm({ ...form, oauthCredentialId: e.target.value })
              }}
            >
              <option value="">Choose…</option>
              {credentials.data?.items.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </Select>
          </Field>

          <Field
            label="Transport"
            htmlFor="mb-transport"
            error={fieldErrors.transport}
            hint="SMTP keeps Exchange's own status codes; Graph avoids the 30/minute SMTP limit but caps messages at 4 MB."
          >
            <Select
              id="mb-transport"
              value={form.transport}
              onChange={(e) => {
                setForm({ ...form, transport: e.target.value as Transport })
              }}
            >
              <option value="smtp">SMTP (XOAUTH2)</option>
              <option value="graph">Microsoft Graph</option>
            </Select>
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field
              label="Messages per minute"
              htmlFor="mb-rate"
              error={fieldErrors.rateLimitPerMin}
              hint="Exchange allows at most 30."
            >
              <Input
                id="mb-rate"
                type="number"
                min={1}
                max={30}
                placeholder="default"
                value={form.rateLimitPerMin}
                onChange={(e) => {
                  setForm({ ...form, rateLimitPerMin: e.target.value })
                }}
              />
            </Field>
            <Field
              label="Concurrent sends"
              htmlFor="mb-conc"
              error={fieldErrors.maxConcurrent}
              hint="Exchange allows at most 3."
            >
              <Input
                id="mb-conc"
                type="number"
                min={1}
                max={3}
                placeholder="default"
                value={form.maxConcurrent}
                onChange={(e) => {
                  setForm({ ...form, maxConcurrent: e.target.value })
                }}
              />
            </Field>
          </div>

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
        title={`Connection test — ${testResult?.mailbox ?? ''}`}
        open={testResult !== undefined}
        onClose={() => {
          setTestResult(undefined)
        }}
      >
        {testResult && (
          <div className="flex flex-col gap-3 text-sm">
            {testResult.result.ok ? (
              <Badge tone="success">Token issued</Badge>
            ) : (
              <Badge tone="danger">Failed at {testResult.result.stage}</Badge>
            )}
            <p>{testResult.result.message}</p>
            {testResult.result.hint && <p className="text-ink-muted">{testResult.result.hint}</p>}
            <div className="flex justify-end">
              <Button
                variant="primary"
                onClick={() => {
                  setTestResult(undefined)
                }}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
