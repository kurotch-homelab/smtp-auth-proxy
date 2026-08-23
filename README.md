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

With Docker Compose:

```bash
cd deploy/compose
cp .env.example .env
```

Generate the encryption key, put it in `.env`, and start:

```bash
docker compose up -d
```

```bash
docker compose exec proxy /usr/local/bin/smtp-auth-proxy adduser --config /etc/smtp-auth-proxy/config.yaml --username admin
```

The generated password is printed once. Open http://localhost:8080, sign in, and
follow the credential screen's **Setup** dialog — it generates the Exchange
Online PowerShell with your values filled in.

On Kubernetes:

```bash
kubectl create secret generic smtp-auth-proxy-encryption --from-literal=key="$(docker run --rm ghcr.io/kurotch-homelab/smtp-auth-proxy:latest genkey -quiet)"
```

```bash
helm install smtp-auth-proxy oci://ghcr.io/kurotch-homelab/charts/smtp-auth-proxy --set encryption.existingSecret=smtp-auth-proxy-encryption
```

For a declarative, GitOps-style deployment, see the bootstrap section of
[`docs/configuration.md`](docs/configuration.md).

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

## Documentation

| Guide | What it covers |
| --- | --- |
| [`docs/setup-m365.md`](docs/setup-m365.md) | The tenant side: app registration, consent, `New-ServicePrincipal`, mailbox permissions |
| [`docs/configuration.md`](docs/configuration.md) | `config.yaml`, secret handling, key rotation, GitOps bootstrap |
| [`docs/architecture.md`](docs/architecture.md) | How a message moves through the proxy, and the trust boundaries |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Working back from an error — including every flavor of `535` |

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
