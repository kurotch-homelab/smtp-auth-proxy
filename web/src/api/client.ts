import type {
  Account,
  AccountWithPassword,
  AuditEntry,
  AuthConfig,
  ConnectionTest,
  Credential,
  CredentialSetup,
  ListResponse,
  Mailbox,
  Message,
  Session,
  Status,
  User,
} from './types'

/**
 * An error carrying what the API said about it.
 *
 * The API returns one shape for every failure, with a machine-readable code, so
 * the UI can react to a specific case without matching on prose.
 */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** Per-field validation messages, keyed by field name. */
  readonly fields: Record<string, string>

  constructor(status: number, code: string, message: string, fields: Record<string, string> = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.fields = fields
  }

  /** The session has gone: expired, revoked, or never existed. */
  get isUnauthorized(): boolean {
    return this.status === 401
  }

  /** The role does not allow this. */
  get isForbidden(): boolean {
    return this.status === 403 && this.code !== 'csrf_failed'
  }
}

interface ApiErrorBody {
  code?: string
  message?: string
  fields?: Record<string, string>
}

/**
 * The CSRF token for the current session.
 *
 * It is held in memory rather than a cookie: a cookie is sent automatically,
 * which is precisely what the token exists to defend against.
 */
let csrfToken = ''

export function setCsrfToken(token: string): void {
  csrfToken = token
}

export function getCsrfToken(): string {
  return csrfToken
}

/** Called when a request comes back unauthorized, so the app can sign out. */
let onUnauthorized: (() => void) | undefined

export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorized = handler
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (method !== 'GET' && method !== 'HEAD' && csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }

  const response = await fetch(path, {
    method,
    headers,
    // The session cookie is HttpOnly, so it has to ride along automatically.
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (response.status === 204) {
    return undefined as T
  }

  if (!response.ok) {
    const parsed = await parseErrorBody(response)
    const error = new ApiError(
      response.status,
      parsed.code ?? 'unknown',
      parsed.message ?? response.statusText,
      parsed.fields ?? {},
    )
    if (error.isUnauthorized) {
      onUnauthorized?.()
    }
    throw error
  }

  return (await response.json()) as T
}

async function parseErrorBody(response: Response): Promise<ApiErrorBody> {
  try {
    return (await response.json()) as ApiErrorBody
  } catch {
    // An HTML error page from something in front of the proxy, or an empty
    // body. Neither is JSON, and neither should crash the UI.
    return { message: `${String(response.status)} ${response.statusText}` }
  }
}

const get = <T>(path: string) => request<T>('GET', path)
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body)
const patch = <T>(path: string, body?: unknown) => request<T>('PATCH', path, body)
const del = <T>(path: string) => request<T>('DELETE', path)

/** Builds a query string, omitting empty values. */
export function queryString(
  params: Record<string, string | number | undefined | string[]>,
): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '') continue
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, item)
    } else {
      search.set(key, String(value))
    }
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}

export const api = {
  auth: {
    config: () => get<AuthConfig>('/api/v1/auth/config'),
    login: (username: string, password: string) =>
      post<Session>('/api/v1/auth/login', { username, password }),
    logout: () => post<void>('/api/v1/auth/logout'),
    me: () => get<Session>('/api/v1/auth/me'),
    changePassword: (currentPassword: string, newPassword: string) =>
      post<void>('/api/v1/auth/password', { currentPassword, newPassword }),
  },

  status: () => get<Status>('/api/v1/status'),

  credentials: {
    list: () => get<ListResponse<Credential>>('/api/v1/credentials'),
    get: (id: string) => get<Credential>(`/api/v1/credentials/${id}`),
    setup: (id: string) => get<CredentialSetup>(`/api/v1/credentials/${id}/setup`),
    create: (body: unknown) => post<Credential>('/api/v1/credentials', body),
    update: (id: string, body: unknown) => patch<Credential>(`/api/v1/credentials/${id}`, body),
    remove: (id: string) => del<void>(`/api/v1/credentials/${id}`),
  },

  mailboxes: {
    list: () => get<ListResponse<Mailbox>>('/api/v1/mailboxes'),
    get: (id: string) => get<Mailbox>(`/api/v1/mailboxes/${id}`),
    create: (body: unknown) => post<Mailbox>('/api/v1/mailboxes', body),
    update: (id: string, body: unknown) => patch<Mailbox>(`/api/v1/mailboxes/${id}`, body),
    remove: (id: string) => del<void>(`/api/v1/mailboxes/${id}`),
    test: (id: string) => post<ConnectionTest>(`/api/v1/mailboxes/${id}/test`),
  },

  accounts: {
    list: () => get<ListResponse<Account>>('/api/v1/accounts'),
    get: (id: string) => get<Account>(`/api/v1/accounts/${id}`),
    create: (body: unknown) => post<AccountWithPassword>('/api/v1/accounts', body),
    update: (id: string, body: unknown) => patch<Account>(`/api/v1/accounts/${id}`, body),
    remove: (id: string) => del<void>(`/api/v1/accounts/${id}`),
    resetPassword: (id: string) =>
      post<{ password: string }>(`/api/v1/accounts/${id}/password`, {}),
  },

  messages: {
    list: (params: Record<string, string | number | undefined | string[]>) =>
      get<ListResponse<Message>>(`/api/v1/messages${queryString(params)}`),
    get: (id: string) => get<Message>(`/api/v1/messages/${id}`),
    bodyUrl: (id: string) => `/api/v1/messages/${id}/body`,
    retry: (id: string) => post<void>(`/api/v1/messages/${id}/retry`),
    hold: (id: string) => post<void>(`/api/v1/messages/${id}/hold`),
    remove: (id: string) => del<void>(`/api/v1/messages/${id}`),
  },

  users: {
    list: () => get<ListResponse<User>>('/api/v1/users'),
    create: (body: unknown) => post<User>('/api/v1/users', body),
    update: (id: string, body: unknown) => patch<User>(`/api/v1/users/${id}`, body),
    remove: (id: string) => del<void>(`/api/v1/users/${id}`),
    setPassword: (id: string, password: string) =>
      post<void>(`/api/v1/users/${id}/password`, { password }),
  },

  audit: {
    list: (params: Record<string, string | number | undefined>) =>
      get<ListResponse<AuditEntry>>(`/api/v1/audit${queryString(params)}`),
  },
}
