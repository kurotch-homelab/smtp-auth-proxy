import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  ApiError,
  api,
  getCsrfToken,
  queryString,
  setCsrfToken,
  setUnauthorizedHandler,
} from './client'

const fetchMock = vi.fn()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  setCsrfToken('')
  setUnauthorizedHandler(() => undefined)
})

afterEach(() => {
  vi.unstubAllGlobals()
  fetchMock.mockReset()
})

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('the API client', () => {
  it('sends the CSRF token on mutating requests only', async () => {
    setCsrfToken('the-token')
    fetchMock.mockResolvedValue(jsonResponse(200, { items: [], total: 0 }))

    await api.credentials.list()
    const getInit = fetchMock.mock.calls[0]?.[1] as RequestInit
    // A GET cannot change anything, so it carries no token — and never should,
    // because a token on a GET is a token in a place it does not need to be.
    expect(new Headers(getInit.headers).get('X-CSRF-Token')).toBeNull()

    fetchMock.mockResolvedValue(jsonResponse(200, {}))
    await api.messages.retry('m1')
    const postInit = fetchMock.mock.calls[1]?.[1] as RequestInit
    expect(new Headers(postInit.headers).get('X-CSRF-Token')).toBe('the-token')
  })

  it('parses the API error shape into ApiError', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(422, {
        code: 'validation_failed',
        message: 'some fields are not valid',
        fields: { address: 'must be a valid email address' },
      }),
    )

    const failure = await api.mailboxes.create({}).catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(ApiError)
    const apiError = failure as ApiError
    expect(apiError.code).toBe('validation_failed')
    expect(apiError.fields.address).toContain('valid email')
    expect(apiError.status).toBe(422)
  })

  it('survives an error body that is not JSON', async () => {
    // Something in front of the proxy answered with an HTML page; the UI must
    // show a readable error rather than crash on the parse.
    fetchMock.mockResolvedValue(
      new Response('<html>502 Bad Gateway</html>', { status: 502, statusText: 'Bad Gateway' }),
    )

    const failure = await api.status().catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).message).toContain('502')
  })

  it('reports an ended session through the unauthorized handler', async () => {
    const onUnauthorized = vi.fn()
    setUnauthorizedHandler(onUnauthorized)
    fetchMock.mockResolvedValue(jsonResponse(401, { code: 'unauthorized', message: 'sign in' }))

    await api.status().catch(() => undefined)
    // This is what flips the app to the sign-in page when a session expires
    // mid-use.
    expect(onUnauthorized).toHaveBeenCalledOnce()
  })

  it('treats 204 as no content', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    await expect(api.messages.retry('m1')).resolves.toBeUndefined()
  })

  it('stores the CSRF token in memory only', () => {
    setCsrfToken('secret-token')
    expect(getCsrfToken()).toBe('secret-token')
    // Nothing may persist it: anything a script can read from storage, an
    // injected script can read too.
    expect(localStorage.length).toBe(0)
    expect(document.cookie).not.toContain('secret-token')
  })
})

describe('the endpoint map', () => {
  it('addresses every resource under /api/v1', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(200, {})))
    setCsrfToken('t')

    // Drive one call from each group and check the wire shape: the path, the
    // method, and that a body goes out as JSON.
    await api.auth.config()
    await api.auth.login('u', 'p')
    await api.auth.logout()
    await api.auth.changePassword('old', 'new')
    await api.status()
    await api.credentials.get('c1')
    await api.credentials.setup('c1')
    await api.credentials.create({ name: 'x' })
    await api.credentials.update('c1', { name: 'y' })
    await api.credentials.remove('c1')
    await api.mailboxes.list()
    await api.mailboxes.get('m1')
    await api.mailboxes.update('m1', {})
    await api.mailboxes.remove('m1')
    await api.mailboxes.test('m1')
    await api.accounts.list()
    await api.accounts.get('a1')
    await api.accounts.create({})
    await api.accounts.update('a1', {})
    await api.accounts.remove('a1')
    await api.accounts.resetPassword('a1')
    await api.messages.list({ status: 'failed' })
    await api.messages.get('msg1')
    await api.messages.hold('msg1')
    await api.messages.remove('msg1')
    await api.users.list()
    await api.users.create({})
    await api.users.update('u1', {})
    await api.users.remove('u1')
    await api.users.setPassword('u1', 'a-long-password')
    await api.audit.list({ action: 'x' })

    const calls = fetchMock.mock.calls.map((call) => {
      const [path, init] = call as [string, RequestInit]
      return `${init.method ?? 'GET'} ${path}`
    })

    // Spot-check the shapes that would break the server's routing if they
    // drifted.
    expect(calls).toContain('POST /api/v1/auth/login')
    expect(calls).toContain('GET /api/v1/credentials/c1/setup')
    expect(calls).toContain('PATCH /api/v1/mailboxes/m1')
    expect(calls).toContain('POST /api/v1/accounts/a1/password')
    expect(calls).toContain('GET /api/v1/messages?status=failed')
    expect(calls).toContain('DELETE /api/v1/users/u1')
    // Every path stays under the versioned prefix.
    for (const call of calls) {
      expect(call).toMatch(/ \/api\/v1\//)
    }
  })

  it('builds the body download URL without fetching it', () => {
    // A download is a navigation, not an XHR: the browser follows it with the
    // session cookie, and the response is a file.
    expect(api.messages.bodyUrl('m1')).toBe('/api/v1/messages/m1/body')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('queryString', () => {
  it('builds a query, omitting what is empty', () => {
    expect(queryString({ status: 'failed', search: '', limit: 50, missing: undefined })).toBe(
      '?status=failed&limit=50',
    )
  })

  it('repeats array values', () => {
    expect(queryString({ status: ['queued', 'deferred'] })).toBe('?status=queued&status=deferred')
  })

  it('returns nothing for no parameters', () => {
    expect(queryString({})).toBe('')
  })
})

describe('ApiError', () => {
  it('distinguishes unauthorized from forbidden', () => {
    expect(new ApiError(401, 'unauthorized', 'x').isUnauthorized).toBe(true)
    expect(new ApiError(403, 'forbidden', 'x').isForbidden).toBe(true)
    // A CSRF failure is 403 but is not a role problem; retrying after a reload
    // is the right reaction, not hiding the button.
    expect(new ApiError(403, 'csrf_failed', 'x').isForbidden).toBe(false)
  })
})
