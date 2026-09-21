import { LicenseFooter } from '@/components/LicenseFooter'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import type { ReactNode } from 'react'
import {
  Avatar,
  Menu,
  MenuTrigger,
  MenuPopover,
  MenuList,
  MenuItem,
} from '@fluentui/react-components'
import {
  Grid24Regular,
  MailInbox24Regular,
  PersonKey24Regular,
  Mail24Regular,
  Key24Regular,
  People24Regular,
  History24Regular,
  Navigation24Regular,
  SignOut24Regular,
  MailArrowUp24Regular,
} from '@fluentui/react-icons'
import { Button } from './ui'
import { useSession } from '@/lib/useSession'
import type { Permission } from '@/api/types'

interface NavItem {
  to: string
  label: string
  description: string
  permission: Permission
  icon: ReactNode
  group: string
}
const navigation: NavItem[] = [
  {
    to: '/',
    label: 'Overview',
    description: 'Monitor delivery and see what needs your attention.',
    permission: 'view.status',
    icon: <Grid24Regular />,
    group: 'Operations',
  },
  {
    to: '/messages',
    label: 'Messages',
    description: 'Inspect deliveries, investigate failures, and manage queued messages.',
    permission: 'view.status',
    icon: <MailInbox24Regular />,
    group: 'Operations',
  },
  {
    to: '/accounts',
    label: 'SMTP accounts',
    description: 'Manage device sign-in and the mailboxes each account can use.',
    permission: 'view.config',
    icon: <PersonKey24Regular />,
    group: 'Connections',
  },
  {
    to: '/mailboxes',
    label: 'Mailboxes',
    description: 'Connect shared mailboxes to your sending credentials.',
    permission: 'view.config',
    icon: <Mail24Regular />,
    group: 'Connections',
  },
  {
    to: '/credentials',
    label: 'OAuth credentials',
    description: 'Manage the Microsoft Entra applications used to send mail.',
    permission: 'view.config',
    icon: <Key24Regular />,
    group: 'Connections',
  },
  {
    to: '/users',
    label: 'Users',
    description: 'Manage access to this administration console.',
    permission: 'users.manage',
    icon: <People24Regular />,
    group: 'Administration',
  },
  {
    to: '/audit',
    label: 'Audit log',
    description: 'Review configuration changes and administrative activity.',
    permission: 'view.audit',
    icon: <History24Regular />,
    group: 'Administration',
  },
]

export function Layout() {
  const { session, can, signOut } = useSession()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const [signingOut, setSigningOut] = useState(false)
  const [navOpen, setNavOpen] = useState(false)
  const visible = navigation.filter((item) => can(item.permission))
  const current = navigation.find((item) => item.to === pathname)
  const name = session?.user.displayName ?? session?.user.username ?? ''
  return (
    <div className="app-shell">
      <a href="#main" className="app-skip">
        Skip to content
      </a>
      <header className="app-topbar">
        <div className="app-brand">
          <span className="app-brand-icon">
            <MailArrowUp24Regular />
          </span>
          <span>smtp-auth-proxy</span>
          <span className="app-brand-label">Admin center</span>
        </div>
        <div className="app-user">
          <Menu>
            <MenuTrigger disableButtonEnhancement>
              <Button variant="ghost" aria-label="User menu" className="app-profile">
                <Avatar name={name} size={28} color="brand" />
                <span>
                  {name}
                  <small>{session?.user.role}</small>
                </span>
              </Button>
            </MenuTrigger>
            <MenuPopover>
              <MenuList>
                <MenuItem
                  onClick={() => {
                    void navigate('/profile')
                  }}
                >
                  Your profile
                </MenuItem>
                <MenuItem
                  icon={<SignOut24Regular />}
                  disabled={signingOut}
                  onClick={() => {
                    setSigningOut(true)
                    void signOut().finally(() => {
                      setSigningOut(false)
                    })
                  }}
                >
                  Sign out
                </MenuItem>
              </MenuList>
            </MenuPopover>
          </Menu>
        </div>
      </header>
      <div className="app-workspace">
        <div className="app-mobile-navigation">
          <Button
            aria-expanded={navOpen}
            aria-controls="app-navigation"
            onClick={() => {
              setNavOpen(!navOpen)
            }}
          >
            <Navigation24Regular /> Navigation
          </Button>
        </div>
        <aside id="app-navigation" className={`app-sidebar ${navOpen ? 'is-open' : ''}`}>
          <nav aria-label="Sections">
            {['Operations', 'Connections', 'Administration'].map((group) => {
              const items = visible.filter((item) => item.group === group)
              return (
                items.length > 0 && (
                  <div className="app-nav-group" key={group}>
                    <p>{group}</p>
                    {items.map((item) => (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        end={item.to === '/'}
                        onClick={() => {
                          setNavOpen(false)
                        }}
                        className={({ isActive }) => `app-nav-item ${isActive ? 'is-active' : ''}`}
                      >
                        {item.icon}
                        <span>{item.label}</span>
                      </NavLink>
                    ))}
                  </div>
                )
              )
            })}
          </nav>
        </aside>
        <main id="main" className="app-main">
          <div className="app-page-heading">
            <h1>{current?.label ?? 'Your profile'}</h1>
            <p>{current?.description ?? 'View your account and manage your sign-in settings.'}</p>
          </div>
          <Outlet />
          <LicenseFooter />
        </main>
      </div>
    </div>
  )
}
