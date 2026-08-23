import { useContext } from 'react'

import { SessionContext } from './sessionContext'
import type { SessionValue } from './sessionContext'

/**
 * useSession returns the signed-in user and what they may do.
 *
 * It lives apart from the provider so that editing the provider does not defeat
 * fast refresh for every screen that reads from it.
 */
export function useSession(): SessionValue {
  const value = useContext(SessionContext)
  if (!value) {
    throw new Error('useSession must be used inside a SessionProvider')
  }
  return value
}
