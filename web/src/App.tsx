/**
 * Placeholder shell. The real admin UI (dashboard, mailboxes, credentials,
 * SMTP accounts, queue, users, audit log) lands in the admin-UI phase; this
 * exists so the build, lint and test pipeline is wired up from day one.
 */
export function App() {
  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1 className="text-2xl font-semibold">smtp-auth-proxy</h1>
      <p className="mt-2 text-sm opacity-70">Admin UI is not implemented yet.</p>
    </main>
  )
}
