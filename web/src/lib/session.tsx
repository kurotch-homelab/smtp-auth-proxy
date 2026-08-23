import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo } from 'react'
import type { ReactNode } from 'react'

import { ApiError, api, setCsrfToken, setUnauthorizedHandler } from '@/api/client'
import { SessionContext } from './sessionContext'
import type { SessionValue } from './sessionContext'

/**
 * SessionProvider holds the signed-in user and the CSRF token.
 *
 * The token lives in memory rather than storage: it exists to prove a request
 * came from this application, and anything a script can read from storage a
 * cross-site scripting bug can read too.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['session'],
    queryFn: async () => {
      try {
        return await api.auth.me()
      } catch (error) {
        // Not being signed in is the normal state on the sign-in page, not an
        // error worth retrying or reporting.
        if (error instanceof ApiError && error.isUnauthorized) return null
        throw error
      }
    },
    retry: false,
    // The session outlives a tab switch; refetching on every focus would put a
    // request on the wire for nothing.
    refetchOnWindowFocus: false,
  })

  const session = data ?? undefined

  useEffect(() => {
    setCsrfToken(session?.csrfToken ?? '')
  }, [session])

  useEffect(() => {
    // A request that comes back unauthorized means the session ended somewhere
    // else — it expired, an administrator disabled the account, or a role
    // changed. Drop it so the app shows the sign-in page rather than a wall of
    // failed requests.
    setUnauthorizedHandler(() => {
      queryClient.setQueryData(['session'], null)
    })
  }, [queryClient])

  const signIn = useCallback(
    async (username: string, password: string) => {
      const next = await api.auth.login(username, password)
      setCsrfToken(next.csrfToken)
      queryClient.setQueryData(['session'], next)
      // Anything fetched while signed out, or as a different user, is stale.
      await queryClient.invalidateQueries()
    },
    [queryClient],
  )

  const signOut = useCallback(async () => {
    try {
      await api.auth.logout()
    } finally {
      setCsrfToken('')
      queryClient.setQueryData(['session'], null)
      // Clear rather than invalidate: none of it should be readable after
      // signing out, not even briefly from the cache.
      queryClient.clear()
    }
  }, [queryClient])

  const refresh = useCallback(async () => {
    await refetch()
  }, [refetch])

  const value = useMemo<SessionValue>(
    () => ({
      session,
      loading: isLoading,
      can: (permission) => session?.permissions.includes(permission) ?? false,
      signIn,
      signOut,
      refresh,
    }),
    [session, isLoading, signIn, signOut, refresh],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
