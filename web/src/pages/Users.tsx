import { ActionsMenu } from '@/components/ActionsMenu'
import { DetailLink as Link } from '@/components/DetailLink'
import { ResourceDetails } from '@/components/ResourceDetails'
import { useListView } from '@/lib/useListView'
import { useConfirm } from '@/components/Confirm'
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
  const confirm = useConfirm()
  const { session } = useSession()
  const queryClient = useQueryClient()

  const users = useQuery({ queryKey: ['users'], queryFn: () => api.users.list() })
  const list = useListView(users.data?.items, (u) => `${u.username} ${u.email ?? ''} ${u.role}`)

  const [passwordFor, setPasswordFor] = useState<User>()
  const [newPassword, setNewPassword] = useState('')
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
    onSuccess: () => {
      setPasswordFor(undefined)
      setNewPassword('')
    },
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
      <ResourceDetails
        kind="users"
        onEdit={async (id) => {
          openEditor(await api.users.get(id))
        }}
      />
      <Card
        title="All users"
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
        {list.controls}
        {users.isLoading ? (
          <Spinner />
        ) : users.error ? (
          <ErrorNotice error={users.error} />
        ) : (
          <>
            <ErrorNotice error={remove.error} className="mb-3" />
            <Table headers={['User', 'Role', 'Source', 'Last sign-in', 'State', '']}>
              {list.items.map((u) => (
                <Row key={u.id}>
                  <Cell>
                    <Link to={list.detailUrl(u.id)}>Details</Link>
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
                    <ActionsMenu>
                      <Button
                        variant="ghost"
                        onClick={() => {
                          openEditor(u)
                        }}
                      >
                        Edit
                      </Button>
                      {u.source === 'local' && (
                        <Button
                          onClick={() => {
                            setPassword.reset()
                            setNewPassword('')
                            setPasswordFor(u)
                          }}
                        >
                          Set password
                        </Button>
                      )}
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
                              void confirm(`Delete ${u.username}?`).then((ok) => {
                                if (ok) remove.mutate(u.id)
                              })
                            }}
                          >
                            Delete
                          </Button>
                        </>
                      )}
                    </ActionsMenu>
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
          ) : null}

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
        open={!!passwordFor}
        title={`Set password — ${passwordFor?.username ?? ''}`}
        onClose={() => {
          setPasswordFor(undefined)
          setNewPassword('')
        }}
      >
        <p className="mb-4">Setting a new password signs this user out everywhere.</p>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (passwordFor) setPassword.mutate({ id: passwordFor.id, password: newPassword })
          }}
        >
          <Field label="New password" htmlFor="reset-user-password">
            <Input
              id="reset-user-password"
              type="password"
              autoComplete="new-password"
              required
              minLength={12}
              value={newPassword}
              onChange={(e) => {
                setNewPassword(e.target.value)
              }}
            />
          </Field>
          <ErrorNotice error={setPassword.error} />
          <Button type="submit" variant="primary" busy={setPassword.isPending}>
            Set password
          </Button>
        </form>
      </Modal>
    </div>
  )
}
