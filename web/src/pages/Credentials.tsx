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
import { useSession } from '@/lib/useSession'
import type { AuthType, Credential, CredentialSetup } from '@/api/types'

interface CredentialForm {
  name: string
  tenantId: string
  clientId: string
  authType: AuthType
  clientSecret: string
  certificatePem: string
  certificateKeyPem: string
  authorityHost: string
  expiresAt: string
}

const emptyForm: CredentialForm = {
  name: '',
  tenantId: '',
  clientId: '',
  authType: 'secret',
  clientSecret: '',
  certificatePem: '',
  certificateKeyPem: '',
  authorityHost: '',
  expiresAt: '',
}

export function CredentialsPage() {
  const { can } = useSession()
  const queryClient = useQueryClient()

  const credentials = useQuery({ queryKey: ['credentials'], queryFn: () => api.credentials.list() })

  const [editing, setEditing] = useState<Credential | 'new' | undefined>()
  const [form, setForm] = useState<CredentialForm>(emptyForm)
  const [setup, setSetup] = useState<{ name: string; data: CredentialSetup } | undefined>()

  const save = useMutation({
    mutationFn: (input: { id?: string; body: unknown }) =>
      input.id ? api.credentials.update(input.id, input.body) : api.credentials.create(input.body),
    onSuccess: async () => {
      setEditing(undefined)
      await queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.credentials.remove(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['credentials'] })
    },
  })

  const loadSetup = useMutation({
    mutationFn: async (credential: Credential) => ({
      name: credential.name,
      data: await api.credentials.setup(credential.id),
    }),
    onSuccess: setSetup,
  })

  const fieldErrors = save.error instanceof ApiError ? save.error.fields : {}

  const openEditor = (credential: Credential | 'new') => {
    save.reset()
    setEditing(credential)
    if (credential === 'new') {
      setForm(emptyForm)
      return
    }
    setForm({
      name: credential.name,
      tenantId: credential.tenantId,
      clientId: credential.clientId,
      authType: credential.authType,
      // Secrets are never returned, so the fields start empty; leaving them
      // empty on save keeps what is stored.
      clientSecret: '',
      certificatePem: '',
      certificateKeyPem: '',
      authorityHost: credential.authorityHost ?? '',
      expiresAt: credential.expiresAt?.slice(0, 10) ?? '',
    })
  }

  const submit = () => {
    const body: Record<string, unknown> = {
      name: form.name,
      tenantId: form.tenantId,
      clientId: form.clientId,
      authType: form.authType,
      authorityHost: form.authorityHost,
    }
    // Only send secret material that was actually entered: an omitted field
    // leaves the stored value alone.
    if (form.clientSecret !== '') body.clientSecret = form.clientSecret
    if (form.certificatePem !== '') body.certificatePem = form.certificatePem
    if (form.certificateKeyPem !== '') body.certificateKeyPem = form.certificateKeyPem
    if (form.expiresAt !== '') body.expiresAt = new Date(form.expiresAt).toISOString()

    save.mutate({ id: editing === 'new' ? undefined : editing?.id, body })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card
        title="OAuth credentials"
        actions={
          can('credentials.manage') && (
            <Button
              variant="primary"
              onClick={() => {
                openEditor('new')
              }}
            >
              New credential
            </Button>
          )
        }
      >
        <p className="mb-4 text-sm text-ink-muted">
          A credential is a Microsoft Entra application registration. One registration can send as
          every mailbox the tenant grants it.
        </p>

        {credentials.isLoading ? (
          <Spinner />
        ) : credentials.error ? (
          <ErrorNotice error={credentials.error} />
        ) : credentials.data && credentials.data.items.length === 0 ? (
          <EmptyState title="No credentials yet">
            Register an application in Microsoft Entra ID, then add its tenant ID, client ID and
            secret here. The setup button generates the Exchange PowerShell for you.
          </EmptyState>
        ) : (
          <>
            <ErrorNotice error={remove.error} className="mb-3" />
            <Table headers={['Name', 'Tenant', 'Type', 'Expiry', 'Mailboxes', '']}>
              {credentials.data?.items.map((c) => (
                <Row key={c.id}>
                  <Cell>
                    <span className="font-medium">{c.name}</span>
                    <p className="text-xs text-ink-muted">{c.clientId}</p>
                  </Cell>
                  <Cell className="text-xs">{c.tenantId}</Cell>
                  <Cell>
                    <Badge>{c.authType}</Badge>
                  </Cell>
                  <Cell>
                    {c.expiresInDays === undefined ? (
                      <span className="text-xs text-ink-muted">not set</span>
                    ) : c.expiresInDays <= 0 ? (
                      <Badge tone="danger">expired</Badge>
                    ) : c.expiresInDays <= 30 ? (
                      <Badge tone="warning">{c.expiresInDays} days</Badge>
                    ) : (
                      <span className="text-xs">{c.expiresInDays} days</span>
                    )}
                  </Cell>
                  <Cell>{c.mailboxCount}</Cell>
                  <Cell>
                    <div className="flex flex-wrap gap-1">
                      <Button
                        variant="ghost"
                        busy={loadSetup.isPending}
                        onClick={() => {
                          loadSetup.mutate(c)
                        }}
                      >
                        Setup
                      </Button>
                      {can('credentials.manage') && c.managedBy !== 'bootstrap' && (
                        <>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              openEditor(c)
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              if (confirm(`Delete ${c.name}?`)) {
                                remove.mutate(c.id)
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
        title={editing === 'new' ? 'New credential' : `Edit ${form.name}`}
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
          <Field label="Name" htmlFor="cred-name" error={fieldErrors.name}>
            <Input
              id="cred-name"
              required
              value={form.name}
              onChange={(e) => {
                setForm({ ...form, name: e.target.value })
              }}
            />
          </Field>

          <Field
            label="Tenant ID"
            htmlFor="cred-tenant"
            error={fieldErrors.tenantId}
            hint="The directory (tenant) ID from the application's overview page."
          >
            <Input
              id="cred-tenant"
              required
              value={form.tenantId}
              onChange={(e) => {
                setForm({ ...form, tenantId: e.target.value })
              }}
            />
          </Field>

          <Field
            label="Client ID"
            htmlFor="cred-client"
            error={fieldErrors.clientId}
            hint="The application (client) ID."
          >
            <Input
              id="cred-client"
              required
              value={form.clientId}
              onChange={(e) => {
                setForm({ ...form, clientId: e.target.value })
              }}
            />
          </Field>

          <Field label="Authentication" htmlFor="cred-type" error={fieldErrors.authType}>
            <Select
              id="cred-type"
              value={form.authType}
              onChange={(e) => {
                setForm({ ...form, authType: e.target.value as AuthType })
              }}
            >
              <option value="secret">Client secret</option>
              <option value="certificate">Certificate</option>
            </Select>
          </Field>

          {form.authType === 'secret' ? (
            <Field
              label="Client secret"
              htmlFor="cred-secret"
              error={fieldErrors.clientSecret}
              hint={
                editing === 'new'
                  ? 'The secret value, shown once by Entra when it is created.'
                  : 'Leave empty to keep the stored secret; enter a value to rotate it.'
              }
            >
              <Input
                id="cred-secret"
                type="password"
                autoComplete="off"
                required={editing === 'new'}
                value={form.clientSecret}
                onChange={(e) => {
                  setForm({ ...form, clientSecret: e.target.value })
                }}
              />
            </Field>
          ) : (
            <>
              <Field
                label="Certificate (PEM)"
                htmlFor="cred-cert"
                error={fieldErrors.certificatePem}
              >
                <textarea
                  id="cred-cert"
                  rows={4}
                  required={editing === 'new'}
                  className="rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs"
                  value={form.certificatePem}
                  onChange={(e) => {
                    setForm({ ...form, certificatePem: e.target.value })
                  }}
                />
              </Field>
              <Field
                label="Private key (PEM)"
                htmlFor="cred-key"
                error={fieldErrors.certificateKeyPem}
                hint={editing !== 'new' ? 'Leave empty to keep the stored key.' : undefined}
              >
                <textarea
                  id="cred-key"
                  rows={4}
                  required={editing === 'new'}
                  className="rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs"
                  value={form.certificateKeyPem}
                  onChange={(e) => {
                    setForm({ ...form, certificateKeyPem: e.target.value })
                  }}
                />
              </Field>
            </>
          )}

          <div className="grid grid-cols-2 gap-4">
            <Field
              label="Expires"
              htmlFor="cred-expiry"
              hint="When the secret or certificate expires; the dashboard warns ahead of it."
            >
              <Input
                id="cred-expiry"
                type="date"
                value={form.expiresAt}
                onChange={(e) => {
                  setForm({ ...form, expiresAt: e.target.value })
                }}
              />
            </Field>
            <Field
              label="Authority host"
              htmlFor="cred-authority"
              error={fieldErrors.authorityHost}
              hint="Only for sovereign clouds; empty uses the configured default."
            >
              <Input
                id="cred-authority"
                placeholder="https://login.microsoftonline.com"
                value={form.authorityHost}
                onChange={(e) => {
                  setForm({ ...form, authorityHost: e.target.value })
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
        title={`Exchange setup — ${setup?.name ?? ''}`}
        open={setup !== undefined}
        onClose={() => {
          setSetup(undefined)
        }}
      >
        {setup && (
          <div className="flex flex-col gap-4 text-sm">
            <p>{setup.data.summary}</p>
            <ol className="list-decimal space-y-1 pl-5">
              {setup.data.steps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
            <CopyField label="PowerShell" value={setup.data.commands} multiline />
            <a
              href={setup.data.docs}
              target="_blank"
              rel="noreferrer"
              className="text-accent underline"
            >
              Microsoft's documentation
            </a>
          </div>
        )}
      </Modal>
    </div>
  )
}
