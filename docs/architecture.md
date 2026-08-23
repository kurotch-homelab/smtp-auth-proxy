# Architecture

```
LAN service ──SMTP AUTH / STARTTLS──▶ :587 ┐
                                           │  smtpsrv    accept, authenticate, sender policy
                                           │     ▼
                                           │  store      persist message + body (SQLite/PostgreSQL)
                                           │     ▼
                                           │  queue      lease, pace, retry
                                           │     ▼
                                           │  transport ─── smtprelay ──▶ smtp.office365.com:587 (XOAUTH2)
                                           │            └── graph ──────▶ graph.microsoft.com (sendMail)
                                           │                    ▲
                                           │  oauth (MSAL) ─────┘        login.microsoftonline.com
                                           │
 operator ──HTTPS──▶ :8080  adminapi + embedded React UI
```

One process, one binary. The admin UI is compiled into it via `go:embed`.

## The path of a message

1. **smtpsrv** accepts the connection. `AUTH` is only offered after STARTTLS;
   PLAIN and LOGIN both carry the password in clear. Authentication resolves an
   SMTP account, its mailboxes and its policy in one step.
2. **policy** decides, from the **From header**, which mailbox the message goes
   out as — or refuses it. The header is what recipients see, so it is what an
   impersonation attempt would forge; the envelope sender is forced to the
   mailbox at delivery time regardless.
3. The message and its body are stored **in one transaction**, and only then
   does the client get its `250`. From here the mail survives restarts.
4. **queue** workers claim messages with a single atomic `UPDATE` — `FOR UPDATE
   SKIP LOCKED` on PostgreSQL — under a lease, so several replicas share one
   queue and a crashed worker's messages are reclaimed when the lease expires.
5. Delivery is paced **per mailbox** below Exchange Online's published limits
   (30 messages/minute, 3 concurrent), because exceeding them buys `4.7.500`,
   not throughput.
6. **transport** speaks either SMTP with SASL XOAUTH2 or the Graph `sendMail`
   API. The XOAUTH2 `user=` field carries the *mailbox* address — that
   substitution is what lets one app registration serve every mailbox.
7. Failures are classified: permanent (5xx) fails the message; anything else is
   retried with jittered exponential backoff. **Authentication failures are
   retried** even though 535 is formally permanent, because they almost always
   mean a fixable tenant setting, and the queue exists so mail is not lost
   while someone fixes it.

## Storage

One schema, two engines. Statements are written once with `?` placeholders and
rebound for PostgreSQL; the few genuine differences (row locking, error codes)
sit behind a `Dialect` interface. SQLite is the zero-dependency deployment;
PostgreSQL is what allows more than one replica.

Secrets at rest — client secrets, certificate keys, TOTP seeds — are sealed
with AES-256-GCM under a keyring. Each ciphertext records which key sealed it
and is bound to its own row, so a value cannot be moved to another row and
still decrypt. Passwords (device and admin) are Argon2id, with the parameters
stored per hash so cost can be raised without a migration.

## Trust boundaries

- The **SMTP listener** trusts nothing: per-IP connection caps, auth failure
  limits, size limits, and one indistinguishable error for every kind of
  authentication failure.
- The **admin interface** is sessions + CSRF + a role table
  (viewer/operator/admin). Every route's required permission is declared, and a
  test walks the router and fails on any route without one.
- The **audit log** is append-only and masks secret-shaped fields before
  writing; it records that a secret changed, never what it changed to.
- **X-Forwarded-For** and the **PROXY protocol** are honored only from
  explicitly trusted networks — otherwise any client could forge its address.
