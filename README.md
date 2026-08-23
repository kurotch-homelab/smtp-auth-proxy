# smtp-auth-proxy

An SMTP relay that lets LAN devices and services which only speak **SMTP-AUTH with a
username and password** keep sending mail through **Microsoft 365**, which now requires
**OAuth 2.0**.

Microsoft retired Basic authentication for SMTP client submission in Exchange Online on
**30 April 2026**. Multifunction printers, NAS boxes, monitoring agents and
line-of-business applications that cannot be updated stop being able to send mail. This
proxy sits between them and Exchange Online: it accepts an ordinary `AUTH LOGIN` /
`AUTH PLAIN` submission on your LAN and re-sends the message as the matching **shared
mailbox** using the OAuth 2.0 client credentials flow.

> **Status:** under active development. See [the roadmap](#roadmap) for what works today.

## How it works

```
LAN service ──SMTP AUTH (STARTTLS)──▶ smtp-auth-proxy ──XOAUTH2 / Graph──▶ Microsoft 365
   printer                              queue + retry                       shared mailbox
   NAS                                  rate limiting                       shared mailbox
   monitoring                           admin UI                            shared mailbox
```

Each LAN service gets its **own** SMTP username and password. The proxy maps that account
to one or more Exchange Online shared mailboxes, so revoking one printer does not touch
anything else, and a single Entra app registration covers every mailbox.

## Features

- **Per-service credentials** — each device authenticates with its own username and
  password (Argon2id hashed), mapped to the shared mailboxes it may send as.
- **Two upstream transports** — SMTP `XOAUTH2` to `smtp.office365.com`, or the Microsoft
  Graph `sendMail` API. Selectable per mailbox.
- **Store and forward** — submissions are queued and retried with exponential backoff, so
  a device that cannot retry does not lose mail when Exchange throttles.
- **Rate limiting that matches Exchange** — Exchange Online caps SMTP client submission at
  30 messages/minute, 3 concurrent connections and 10,000 recipients/day per mailbox. The
  proxy enforces its own budget below those limits instead of letting mail bounce.
- **Sender enforcement** — an account may only send as the addresses you allow; anything
  else is rejected (or rewritten, if you prefer).
- **Web admin UI** — local users plus OIDC single sign-on, three roles
  (admin / operator / viewer) and an audit log of every change.
- **Runs anywhere** — a single ~9 MB container image, deployable with Docker Compose or
  the bundled Helm chart. SQLite for a one-container setup, PostgreSQL for HA.

## Quick start

Not yet published — build from source for now:

```bash
make web-build && make build && ./bin/smtp-auth-proxy version
```

## Microsoft 365 prerequisites

The proxy cannot work around tenant configuration; a **tenant administrator** must grant
it access once. In short:

1. Register an application in Microsoft Entra ID.
2. Add the **application** permission `SMTP.SendAsApp` (Office 365 Exchange Online) and
   grant admin consent.
3. Register the service principal in Exchange with `New-ServicePrincipal`, using the
   Object ID from **Enterprise applications** — not from **App registrations**.
4. Grant it access to each mailbox with `Add-MailboxPermission`.

The admin UI generates these PowerShell commands with your values filled in. Full walkthrough:
[`docs/setup-m365.md`](docs/setup-m365.md).

## Roadmap

| Stage | Status |
| --- | --- |
| Repository, CI, dependency automation | ✅ |
| Configuration, database, secret encryption | 🚧 |
| SMTP ingress, sender policy, spool | ⬜ |
| OAuth tokens, XOAUTH2 relay, queue workers | ⬜ |
| Microsoft Graph transport | ⬜ |
| Admin API, authentication, RBAC, audit log | ⬜ |
| Admin UI | ⬜ |
| Docker Compose and Helm chart | ⬜ |
| Documentation and releases | ⬜ |

## Development

```bash
make help
```

```bash
make lint test
```

Requires Go 1.25+, Node 22+ and Docker. Tests run against SQLite by default; set
`TEST_POSTGRES_DSN` to also exercise the PostgreSQL code paths.

## License

[Apache-2.0](LICENSE)
