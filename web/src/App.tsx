import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import { Layout } from './components/Layout'
import { Spinner } from './components/ui'
import { SessionProvider } from './lib/session'
import { useSession } from './lib/useSession'
import { AccountsPage } from './pages/Accounts'
import { AuditPage } from './pages/Audit'
import { CredentialsPage } from './pages/Credentials'
import { DashboardPage } from './pages/Dashboard'
import { LoginPage } from './pages/Login'
import { MailboxesPage } from './pages/Mailboxes'
import { ProfilePage } from './pages/Profile'
import { QueuePage } from './pages/Queue'
import { UsersPage } from './pages/Users'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // One retry for transient blips; the operator can always reload. More
      // would mean multiplying load exactly when something is wrong.
      retry: 1,
    },
  },
})

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SessionProvider>
        <BrowserRouter>
          <Routed />
        </BrowserRouter>
      </SessionProvider>
    </QueryClientProvider>
  )
}

function Routed() {
  const { session, loading } = useSession()

  if (loading) {
    return (
      <div className="flex min-h-dvh items-center justify-center">
        <Spinner />
      </div>
    )
  }

  if (!session) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        {/* Whatever was being looked at, an ended session means the sign-in
            page — not a wall of failed requests. */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="/queue" element={<QueuePage />} />
        <Route path="/accounts" element={<AccountsPage />} />
        <Route path="/mailboxes" element={<MailboxesPage />} />
        <Route path="/credentials" element={<CredentialsPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/profile" element={<ProfilePage />} />
      </Route>
      {/* Being signed in makes the sign-in page pointless. */}
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
