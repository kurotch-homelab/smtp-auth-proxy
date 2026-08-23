import { NavLink, Outlet } from 'react-router-dom'
import { useState } from 'react'

import { Button } from './ui'
import { useSession } from '@/lib/useSession'
import type { Permission } from '@/api/types'

interface NavItem {
  to: string
  label: string
  /** The permission needed to see it; undefined means everyone signed in. */
  permission?: Permission
}

const navigation: NavItem[] = [
  { to: '/', label: 'Dashboard', permission: 'view.status' },
  { to: '/queue', label: 'Queue', permission: 'view.status' },
  { to: '/accounts', label: 'SMTP accounts', permission: 'view.config' },
  { to: '/mailboxes', label: 'Mailboxes', permission: 'view.config' },
  { to: '/credentials', label: 'Credentials', permission: 'view.config' },
  { to: '/users', label: 'Users', permission: 'users.manage' },
  { to: '/audit', label: 'Audit log', permission: 'view.audit' },
]

/**
 * The application shell.
 *
 * Navigation is filtered by permission so a viewer is not offered pages that
 * would only refuse them. The API enforces the same rules regardless — hiding a
 * link is a courtesy, not a control.
 */
export function Layout() {
  const { session, can, signOut } = useSession()
  const [signingOut, setSigningOut] = useState(false)

  const visible = navigation.filter((item) => !item.permission || can(item.permission))

  return (
    <div className="min-h-dvh">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:m-2 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-accent-ink"
      >
        Skip to content
      </a>

      <header className="border-b border-border bg-surface-raised">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-4 py-3">
          <span className="font-semibold">smtp-auth-proxy</span>

          <nav aria-label="Sections" className="flex flex-wrap gap-1">
            {visible.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `rounded-md px-2.5 py-1.5 text-sm transition ${
                    isActive ? 'bg-accent text-accent-ink' : 'hover:bg-border/50'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3 text-sm">
            <NavLink to="/profile" className="text-ink-muted hover:text-ink">
              {session?.user.displayName ?? session?.user.username}
              <span className="ml-1 text-xs">({session?.user.role})</span>
            </NavLink>
            <Button
              variant="ghost"
              busy={signingOut}
              onClick={() => {
                setSigningOut(true)
                void signOut().finally(() => {
                  setSigningOut(false)
                })
              }}
            >
              Sign out
            </Button>
          </div>
        </div>
      </header>

      <main id="main" className="mx-auto max-w-6xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
