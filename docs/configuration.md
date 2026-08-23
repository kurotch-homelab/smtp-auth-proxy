# Configuration

Two layers, deliberately separate:

| Layer | Where | Changed by |
| --- | --- | --- |
| Static: listeners, TLS, database, encryption keys, admin settings | `config.yaml` | editing the file, restart |
| Runtime: credentials, mailboxes, SMTP accounts, users | the database | the admin interface (or bootstrap) |

[`config.example.yaml`](../config.example.yaml) documents every static key
inline; this page covers what is not obvious from reading it.

## Value expansion

Any value may reference the environment or a mounted file:

```yaml
encryption:
  keys: ["${SMTP_AUTH_PROXY_ENCRYPTION_KEY}"]
database:
  dsn: ${file:/run/secrets/database-dsn}
oidc:
  client_secret: ${OIDC_CLIENT_SECRET:-}
```

`${VAR}` fails startup when unset — a proxy that starts with an empty client
secret fails much later and much more confusingly. `${VAR:-default}` supplies
a fallback. `${file:/path}` reads a file and trims the trailing newline that
mounted secrets always carry. References inside YAML comments are ignored.

## The encryption key

`smtp-auth-proxy genkey` generates one. It seals every stored secret; treat it
accordingly. To rotate, generate a second key and list it **first**, keeping
the old one after it:

```yaml
encryption:
  keys:
    - ${NEW_KEY}   # seals everything written from now on
    - ${OLD_KEY}   # still decrypts what was written before
```

Values re-encrypt as they are next edited. Dropping the old key before then
makes those rows unreadable — the error will say which key is missing.

## Validation and warnings

Startup validation reports **every** problem at once, and refuses
configurations that are wrong rather than unusual: an unauthenticated
listener (an open relay), a lease shorter than the upstream timeout (double
delivery), per-mailbox limits above Exchange's own. Legal-but-notable choices
— plaintext auth, self-signed TLS, SSO signup straight to admin — start the
proxy and are logged as warnings instead. `serve --check` runs both without
starting anything.

## Bootstrap (GitOps)

`bootstrap.mode: apply-once` seeds credentials, mailboxes and accounts from a
file on first start, then leaves the database to the admin interface.
`reconcile` reapplies the file on every start and marks the declared objects
read-only in the UI, which is the mode for a deployment whose source of truth
is a repository.

```yaml
# bootstrap.yaml — secrets stay in the environment or mounted files.
credentials:
  - name: primary
    tenant_id: 11111111-1111-1111-1111-111111111111
    client_id: 22222222-2222-2222-2222-222222222222
    client_secret: ${file:/run/secrets/entra-client-secret}

mailboxes:
  - address: scanner@example.com
    credential: primary

accounts:
  - username: svc-scanner
    # From `smtp-auth-proxy passwd` — the hash, never the password.
    password_hash: $argon2id$v=19$...
    mailboxes: [scanner@example.com]
```

The file's validation refuses a plaintext password in `password_hash`
(hashes come from `smtp-auth-proxy passwd`), wildcard sender patterns, and
limits above what Exchange Online allows — the same rules the admin
interface enforces.
