/**
 * Types mirroring the JSON the management API returns.
 *
 * They are written by hand rather than generated: the API is small, and a
 * mismatch shows up immediately in `tsc` against the handlers' own tests.
 */

export type Role = 'admin' | 'operator' | 'viewer'

export type Permission =
  | 'view.status'
  | 'view.config'
  | 'view.audit'
  | 'queue.manage'
  | 'queue.read_body'
  | 'accounts.manage'
  | 'mailboxes.manage'
  | 'credentials.manage'
  | 'users.manage'
  | 'settings.manage'

export type Transport = 'smtp' | 'graph'
export type AuthType = 'secret' | 'certificate'
export type FromPolicy = 'reject' | 'rewrite' | 'passthrough'
export type ManagedBy = 'ui' | 'bootstrap'

export type MessageStatus = 'queued' | 'sending' | 'sent' | 'deferred' | 'failed' | 'held'

export interface User {
  id: string
  username: string
  email?: string
  displayName?: string
  role: Role
  source: 'local' | 'oidc'
  disabled: boolean
  hasPassword: boolean
  lockedUntil?: string
  lastLoginAt?: string
  createdAt: string
  updatedAt: string
}

export interface Session {
  user: User
  permissions: Permission[]
  csrfToken: string
  expiresAt: string
}

export interface AuthConfig {
  localEnabled: boolean
  oidcEnabled: boolean
  oidcLabel?: string
}

export interface Credential {
  id: string
  name: string
  tenantId: string
  clientId: string
  authType: AuthType
  hasSecret: boolean
  certificateThumbprint?: string
  authorityHost?: string
  expiresAt?: string
  expiresInDays?: number
  managedBy: ManagedBy
  mailboxCount: number
  createdAt: string
  updatedAt: string
}

export interface CredentialSetup {
  summary: string
  steps: string[]
  commands: string
  docs: string
}

export interface Mailbox {
  id: string
  address: string
  displayName?: string
  oauthCredentialId: string
  credentialName?: string
  transport: Transport
  rateLimitPerMin?: number
  maxConcurrent?: number
  enabled: boolean
  managedBy: ManagedBy
  createdAt: string
  updatedAt: string
}

export interface Account {
  id: string
  username: string
  description?: string
  defaultMailboxId?: string
  mailboxIds: string[]
  mailboxAddresses: string[]
  allowedSenders: string[]
  fromPolicy: FromPolicy
  allowCidrs: string[]
  rateLimitPerMin?: number
  enabled: boolean
  lastUsedAt?: string
  managedBy: ManagedBy
  createdAt: string
  updatedAt: string
}

/** Returned only when an account is created or its password is reset. */
export interface AccountWithPassword extends Account {
  password?: string
}

export interface Message {
  id: string
  accountUsername?: string
  mailboxAddress?: string
  envelopeFrom: string
  headerFrom?: string
  recipients: string[]
  recipientCount: number
  sizeBytes: number
  subject?: string
  messageId?: string
  status: MessageStatus
  attempts: number
  nextAttemptAt?: string
  lastError?: string
  lastErrorCode?: string
  lastErrorPermanent: boolean
  clientIp?: string
  receivedAt: string
  sentAt?: string
}

export interface AuditEntry {
  id: string
  at: string
  actorType: 'user' | 'system' | 'bootstrap'
  actorId?: string
  actorName?: string
  action: string
  targetType?: string
  targetId?: string
  targetName?: string
  details: string
  result: 'success' | 'failure'
  ip?: string
  userAgent?: string
}

export interface ExpiringCredential {
  id: string
  name: string
  expiresAt: string
  expiresInDays: number
}

export interface Status {
  version: string
  queueByStatus: Partial<Record<MessageStatus, number>>
  mailboxes: number
  accounts: number
  credentials: number
  expiringCredentials: ExpiringCredential[]
  recentFailures: Message[]
  authFailureCount: number
}

export interface ConnectionTest {
  ok: boolean
  stage: string
  message: string
  hint?: string
}

export interface ListResponse<T> {
  items: T[]
  total: number
}
