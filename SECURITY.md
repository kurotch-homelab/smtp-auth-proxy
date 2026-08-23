# Security policy

## Reporting a vulnerability

Please report security issues through
[GitHub's private vulnerability reporting](https://github.com/kurotch-homelab/smtp-auth-proxy/security/advisories/new)
rather than opening a public issue.

Include what an attacker gains, how to reproduce it, and the version or commit you
tested. You can expect an acknowledgement within a week.

## What is in scope

This proxy holds credentials for sending mail as your organization's mailboxes, so the
sensitive areas are:

- **Stored secrets** — OAuth client secrets, certificate private keys and TOTP seeds are
  encrypted with AES-256-GCM using a key supplied through the environment. Anything that
  exposes them in plaintext (logs, API responses, error messages, backups) is a
  vulnerability.
- **Sender enforcement** — an SMTP account being able to send as a mailbox it was not
  granted is a vulnerability, not a misconfiguration.
- **Admin authentication and authorization** — session handling, CSRF protection, OIDC
  claim-to-role mapping, and any path where a `viewer` or `operator` can perform an
  `admin` action.
- **Token handling** — access tokens must never appear in logs, metrics or the admin API.

## What is out of scope

- Exposing the SMTP listener to the public internet. It is designed for a trusted LAN;
  the sender policy is not a substitute for network isolation.
- Running with `allow_insecure_auth: true`, which permits plaintext credentials over an
  unencrypted connection. It exists for devices that cannot do TLS at all, and the
  trade-off is documented.
- Denial of service caused by the deliberately conservative Exchange Online rate limits.

## Supported versions

Until 1.0, only the latest release receives fixes.
