import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'

import { api } from '@/api/client'
import { Button, ErrorNotice, Field, Input } from '@/components/ui'
import { useSession } from '@/lib/useSession'

/** Reasons the single sign-on callback can send the browser back here. */
const ssoErrors: Record<string, string> = {
  sso_failed: 'Single sign-on did not complete. Check the proxy logs for the reason.',
  sso_expired: 'That sign-in attempt expired. Please try again.',
  sso_no_role:
    'Your identity provider authenticated you, but none of your groups map to a role in this proxy.',
  sso_unknown_user:
    'Your account has not been added to this proxy, and automatic provisioning is switched off.',
}

export function LoginPage() {
  const { signIn } = useSession()
  const [params] = useSearchParams()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<unknown>()
  const [busy, setBusy] = useState(false)

  const { data: config } = useQuery({
    queryKey: ['auth-config'],
    queryFn: () => api.auth.config(),
    retry: false,
  })

  const ssoError = params.get('error')

  return (
    <div className="mx-auto flex min-h-dvh max-w-sm flex-col justify-center gap-6 px-4">
      <div>
        <h1 className="text-xl font-semibold">smtp-auth-proxy</h1>
        <p className="text-sm text-ink-muted">Sign in to manage the proxy.</p>
      </div>

      {ssoError && (
        <ErrorNotice error={ssoErrors[ssoError] ?? 'Single sign-on did not complete.'} />
      )}

      {config?.localEnabled !== false && (
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            setError(undefined)
            setBusy(true)
            signIn(username, password)
              .catch(setError)
              .finally(() => {
                setBusy(false)
              })
          }}
        >
          <Field label="Username" htmlFor="username">
            <Input
              id="username"
              name="username"
              autoComplete="username"
              required
              value={username}
              onChange={(e) => {
                setUsername(e.target.value)
              }}
            />
          </Field>

          <Field label="Password" htmlFor="password">
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => {
                setPassword(e.target.value)
              }}
            />
          </Field>

          <ErrorNotice error={error} />

          <Button type="submit" variant="primary" busy={busy}>
            Sign in
          </Button>
        </form>
      )}

      {config?.oidcEnabled && (
        <>
          {config.localEnabled && (
            <div className="flex items-center gap-3 text-xs text-ink-muted">
              <span className="h-px flex-1 bg-border" />
              or
              <span className="h-px flex-1 bg-border" />
            </div>
          )}
          {/* A full navigation, not fetch: the provider redirects the browser,
              and an XHR cannot follow that. */}
          <a
            href="/api/v1/auth/oidc/start"
            className="rounded-md border border-border bg-surface-raised px-3 py-2 text-center text-sm font-medium hover:bg-border/40"
          >
            {config.oidcLabel ?? 'Single sign-on'}
          </a>
        </>
      )}
    </div>
  )
}
