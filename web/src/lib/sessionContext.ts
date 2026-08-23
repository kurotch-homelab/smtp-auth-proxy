import { createContext } from 'react'

import type { Permission, Session } from '@/api/types'

/** What the signed-in user is, and what they may do. */
export interface SessionValue {
  session: Session | undefined
  loading: boolean
  /** Reports whether the signed-in user holds a permission. */
  can: (permission: Permission) => boolean
  signIn: (username: string, password: string) => Promise<void>
  signOut: () => Promise<void>
  refresh: () => Promise<void>
}

/**
 * The context lives in its own module so the provider file exports only a
 * component, which is what keeps fast refresh working while editing it.
 */
export const SessionContext = createContext<SessionValue | undefined>(undefined)
