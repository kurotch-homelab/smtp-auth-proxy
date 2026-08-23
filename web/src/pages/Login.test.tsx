import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { LoginPage } from './Login'
import { SessionContext } from '@/lib/sessionContext'
import type { SessionValue } from '@/lib/sessionContext'

const fetchMock = vi.fn()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
  fetchMock.mockReset()
})

function renderLogin(overrides: Partial<SessionValue> = {}) {
  const value: SessionValue = {
    session: undefined,
    loading: false,
    can: () => false,
    signIn: vi.fn().mockResolvedValue(undefined),
    signOut: vi.fn().mockResolvedValue(undefined),
    refresh: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }

  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <SessionContext.Provider value={value}>
        <MemoryRouter>
          <LoginPage />
        </MemoryRouter>
      </SessionContext.Provider>
    </QueryClientProvider>,
  )
  return value
}

function authConfig(body: unknown) {
  fetchMock.mockResolvedValue(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
}

describe('the sign-in page', () => {
  it('submits the entered credentials', async () => {
    authConfig({ localEnabled: true, oidcEnabled: false })
    const value = renderLogin()

    await userEvent.type(screen.getByLabelText('Username'), 'alice')
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(value.signIn).toHaveBeenCalledWith('alice', 'correct horse')
  })

  it('shows the API error when sign-in is refused', async () => {
    authConfig({ localEnabled: true, oidcEnabled: false })
    renderLogin({
      signIn: vi.fn().mockRejectedValue(new Error('incorrect username or password')),
    })

    await userEvent.type(screen.getByLabelText('Username'), 'alice')
    await userEvent.type(screen.getByLabelText('Password'), 'wrong')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('incorrect username or password')
  })

  it('offers single sign-on when it is configured', async () => {
    authConfig({ localEnabled: true, oidcEnabled: true, oidcLabel: 'Corporate sign-on' })
    renderLogin()

    // A link, not a button: the provider redirects the browser, which an XHR
    // cannot follow.
    const link = await screen.findByRole('link', { name: 'Corporate sign-on' })
    expect(link).toHaveAttribute('href', '/api/v1/auth/oidc/start')
  })

  it('explains a failed single sign-on', async () => {
    authConfig({ localEnabled: true, oidcEnabled: true })
    render(
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
        <SessionContext.Provider
          value={{
            session: undefined,
            loading: false,
            can: () => false,
            signIn: vi.fn(),
            signOut: vi.fn(),
            refresh: vi.fn(),
          }}
        >
          <MemoryRouter initialEntries={['/login?error=sso_no_role']}>
            <LoginPage />
          </MemoryRouter>
        </SessionContext.Provider>
      </QueryClientProvider>,
    )

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/none of your groups map/)
    })
  })
})
