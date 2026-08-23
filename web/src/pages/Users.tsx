import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'

import { ApiError, api } from '@/api/client'
import { Modal } from '@/components/Modal'
import {
  Badge,
  Button,
  Card,
  Cell,
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
import type { Role, User } from '@/api/types'

interface UserForm {
  username: string
  email: string
  displayName: string
  role: Role
  password: string
}

const emptyForm: UserForm = {
  username: '',
  email: '',
  displayName: '',
  role: 'viewer',
  password: '',
}

export function UsersPage() {
  const { session } = useSession()
  const queryClient = useQueryClient()

  const users = useQuery({ queryKey: ['users'], queryFn: () => api.users.list() })

  const [editing, setEditing] = useState<User | 'new' | undefined>()
  const [form, setForm] = useState<UserForm>(emptyForm)

  const save = useMutation({
    mutationFn: (input: { id?: string; body: unknown }) =>
      input.id ? api.users.update(input.id, input.body) : api.users.create(input.body),
    onSuccess: async () => {
      setEditing(undefined)
      await queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const remove = useMutation({
    mutationFn: (id: string) => api.users.remove(id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const setPassword = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      api.users.setPassword(id, password),
  })

  const fieldErrors = save.error instanceof ApiError ? save.error.fields : {}

  const openEditor = (user: User | 'new') => {
    save.reset()
    setEditing(user)
    if (user === 'new') {
      setForm(emptyForm)
      return
    }
    setForm({
      username: user.username,
      email: user.email ?? '',
      displayName: user.displayName ?? '',
      role: user.role,
      password: '',
    })
  }

  const submit = () => {
    if (editing === 'new') {
      save.mutate({ body: form })
      return
    }
    save.mutate({
      id: editing?.id,
      body: { email: form.email, displayName: form.displayName, role: form.role },
    })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card
        title="Administrators"
        actions={
          <Button
            variant="primary"
            onClick={() => {
              openEditor('new')
            }}
          >
            New user
          </Button>
        }
      >
        {users.isLoading ? (
          <Spinner />
        ) : users.error ? (
          <ErrorNotice error={users.error} />
        ) : (
          <>
            <ErrorNotice error={remove.error} className="mb-3" />
            <Table headers={['User', 'Role', 'Source', 'Last sign-in', 'State', '']}>
              {users.data?.items.map((u) => (
                <Row key={u.id}>
                  <Cell>
                    <span className="font-medium">{u.displayName ?? u.username}</span>
                    <p className="text-xs text-ink-muted">
                      {u.username}
                      {u.email && ` · ${u.email}`}
                    </p>
                  </Cell>
                  <Cell>
                    <Badge tone={u.role === 'admin' ? 'accent' : 'neutral'}>{u.role}</Badge>
                  </Cell>
                  <Cell>{u.source === 'oidc' ? 'Single sign-on' : 'Password'}</Cell>
                  <Cell className="whitespace-nowrap">{formatRelative(u.lastLoginAt)}</Cell>
                  <Cell>
                    {u.disabled ? (
                      <Badge tone="danger">disabled</Badge>
                    ) : (
                      <Badge tone="success">active</Badge>
                    )}
                  </Cell>
                  <Cell>
                    <div className="flex flex-wrap gap-1">
                      <Button
                        variant="ghost"
                        onClick={() => {
                          openEditor(u)
                        }}
                      >
                        Edit
                      </Button>
                      {u.id !== session?.user.id && (
                        <>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              save.mutate({ id: u.id, body: { disabled: !u.disabled } })
                            }}
                          >
                            {u.disabled ? 'Enable' : 'Disable'}
                          </Button>
                          <Button
                            variant="ghost"
                            onClick={() => {
                              if (confirm(`Delete ${u.username}?`)) {
                                remove.mutate(u.id)
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
        title={editing === 'new' ? 'New user' : `Edit ${form.username}`}
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
          {editing === 'new' && (
            <Field label="Username" htmlFor="user-name" error={fieldErrors.username}>
              <Input
                id="user-name"
                required
                value={form.username}
                onChange={(e) => {
                  setForm({ ...form, username: e.target.value })
                }}
              />
            </Field>
          )}

          <Field label="Display name" htmlFor="user-display">
            <Input
              id="user-display"
              value={form.displayName}
              onChange={(e) => {
                setForm({ ...form, displayName: e.target.value })
              }}
            />
          </Field>

          <Field label="Email" htmlFor="user-email" error={fieldErrors.email}>
            <Input
              id="user-email"
              type="email"
              value={form.email}
              onChange={(e) => {
                setForm({ ...form, email: e.target.value })
              }}
            />
          </Field>

          <Field
            label="Role"
            htmlFor="user-role"
            error={fieldErrors.role}
            hint="Viewers read. Operators also work the queue. Admins also change configuration."
          >
            <Select
              id="user-role"
              value={form.role}
              onChange={(e) => {
                setForm({ ...form, role: e.target.value as Role })
              }}
            >
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
            </Select>
          </Field>

          {editing === 'new' ? (
            <Field
              label="Password"
              htmlFor="user-password"
              error={fieldErrors.password}
              hint="At least 12 characters."
            >
              <Input
                id="user-password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                value={form.password}
                onChange={(e) => {
                  setForm({ ...form, password: e.target.value })
                }}
              />
            </Field>
          ) : (
            editing &&
            editing.source === 'local' && (
              <Field
                label="Set a new password"
                htmlFor="user-password"
                hint="Leave empty to keep the current one. Setting it signs the user out everywhere."
              >
                <div className="flex gap-2">
                  <Input
                    id="user-password"
                    type="password"
                    autoComplete="new-password"
                    minLength={12}
                    value={form.password}
                    onChange={(e) => {
                      setForm({ ...form, password: e.target.value })
                    }}
                  />
                  <Button
                    type="button"
                    busy={setPassword.isPending}
                    disabled={form.password.length < 12}
                    onClick={() => {
                      setPassword.mutate({ id: editing.id, password: form.password })
                    }}
                  >
                    Set
                  </Button>
                </div>
              </Field>
            )
          )}

          <ErrorNotice error={save.error} />
          <ErrorNotice error={setPassword.error} />

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
    </div>
  )
}
