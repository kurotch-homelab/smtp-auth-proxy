# Daily operations

The light Fluent 2 interface separates operations, connections and administration.
Start with Overview's failed/retrying messages and expiring credentials, then
open the affected resource. Messages lives at `/messages`; `/queue` redirects
while retaining query parameters. Message details use `?message=ID`; connection
and user details use `?id=ID`. Filters and pagination remain in the URL.

SMTP accounts, mailboxes and OAuth credentials remain separate resources.
Configuration-file managed entries identify `bootstrap.path` as the source of
changes. Regular editing and secret/password replacement are separate actions.
Stored secrets are never returned by the API. Credential replacement shows the
mailboxes sharing the credential.

## Diagnostics

Mailbox details provide two distinct actions:

* **Check authentication** obtains an OAuth token. This does not test delivery.
* **Send test email** confirms one recipient and enqueues a fixed test message.
  The normal transport, rate limiter and retry worker process it. A `sent` result
  means Microsoft 365 accepted the message, not that it arrived in the inbox.
  Neither action tests a device's SMTP login.

Administrators and operators have `diagnostics.run`. Viewers may read configuration
facts but cannot execute diagnostics. Existing configuration, secret and message
body permissions are unchanged.

API routes (under `/api/v1`):

| Method | Route | Permission |
| --- | --- | --- |
| GET | `/mailboxes/{id}/diagnostics` | `view.config` |
| POST | `/mailboxes/{id}/test` | `diagnostics.run` |
| POST | `/mailboxes/{id}/test-send` | `diagnostics.run` |

`test-send` accepts `{"requestId":"UUID","recipient":"one@example.com"}` and
returns HTTP 202 with `messageId` and `created`. Poll the existing
`GET /messages/{id}` endpoint for progress. POST still requires a session and CSRF
token. Repeating an identical actor/request ID returns the same message; changing
its mailbox or recipient returns 409. After the message is purged or deleted,
the reservation remains and returns 409 rather than sending another message.
Only an explicitly new request ID starts another test.

Messages expose `origin` (`smtp` or `diagnostic`), `smtpAccountId` and `mailboxId`.
A diagnostic has no SMTP account. The request, queue row, body and actor audit
entry commit together. Deleted relations lose their IDs while historical names
remain. Migration 0002 adds these fields and reservations for both databases;
existing messages default to `smtp`.

## Queue actions

Retry accepts only `failed`, `deferred` and `held`. Hold accepts only `queued`,
`deferred` and `failed`. Deleting a `sent` message removes its history and body.
Active `sending` messages cannot be retried, held or deleted by an operator;
expired worker leases are recovered by the existing worker process. These checks
are atomic database predicates and return 409 for conflicting states.

## Distribution licenses

The login page and admin footer link to `/licenses` and its download. The
standalone `licenses` command needs neither configuration nor a database.
See [the generator instructions](../tools/licenses/README.md) for dependency
updates and the checked-in notices shared by binaries, archives and images.

## Verification

Implementation checks include the full Go test suite with the race detector and
`e2e` tag on Linux, both SQLite and PostgreSQL repository/API state checks, and
local fake Entra/SMTP/Graph endpoints. No test sends mail to Microsoft 365.
Web type checking, lint, formatting, 23 unit/component tests, and production
builds pass. Browser checks cover 390px and desktop widths, keyboard focus
restoration, direct detail URLs, retained filters, viewer permissions, missing
messages and status-fetch errors.

Local distribution verification builds Linux/macOS amd64/arm64 binaries and
archives and compares their notices with the Docker file and embedded CLI output.
Vite reports a non-failing bundle-size warning (about 214 KB gzip for the JS entry).
