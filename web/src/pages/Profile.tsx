import { useMutation } from '@tanstack/react-query'
import { useState } from 'react'

import { ApiError, api } from '@/api/client'
import { Button, Card, ErrorNotice, Field, Input } from '@/components/ui'
import { useSession } from '@/lib/useSession'

export function ProfilePage() {
  const { session } = useSession()

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')

  const change = useMutation({
    mutationFn: () => api.auth.changePassword(currentPassword, newPassword),
    // A successful change revokes every session, so the next request lands on
    // the sign-in page by itself; nothing to do here.
  })

  const fieldErrors = change.error instanceof ApiError ? change.error.fields : {}
  const isLocal = session?.user.source === 'local'

  return (
    <div className="flex max-w-md flex-col gap-4">
      <Card title="Your account">
        <dl className="grid grid-cols-2 gap-2 text-sm">
          <dt className="text-ink-muted">Username</dt>
          <dd>{session?.user.username}</dd>
          <dt className="text-ink-muted">Role</dt>
          <dd>{session?.user.role}</dd>
          <dt className="text-ink-muted">Signs in with</dt>
          <dd>{isLocal ? 'Password' : 'Single sign-on'}</dd>
        </dl>
      </Card>

      {isLocal ? (
        <Card title="Change password">
          <form
            className="flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault()
              change.mutate()
            }}
          >
            <Field label="Current password" htmlFor="pw-current">
              <Input
                id="pw-current"
                type="password"
                autoComplete="current-password"
                required
                value={currentPassword}
                onChange={(e) => {
                  setCurrentPassword(e.target.value)
                }}
              />
            </Field>
            <Field
              label="New password"
              htmlFor="pw-new"
              error={fieldErrors.newPassword}
              hint="At least 12 characters. Changing it signs you out everywhere."
            >
              <Input
                id="pw-new"
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

            <ErrorNotice error={change.error} />

            <Button type="submit" variant="primary" busy={change.isPending}>
              Change password
            </Button>
          </form>
        </Card>
      ) : (
        <Card title="Password">
          <p className="text-sm text-ink-muted">
            This account signs in through your identity provider; change the password there.
          </p>
        </Card>
      )}
    </div>
  )
}
