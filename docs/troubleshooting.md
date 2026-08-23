# Troubleshooting

Work top-down: each section assumes the ones before it pass.

## The device cannot connect to the proxy

- `nc <proxy> 587` from the device's network. No banner → a firewall, a
  NetworkPolicy, or the Service is not reaching the pod.
- The banner appears but authentication is never offered → the connection is
  not encrypted yet. The proxy only advertises `AUTH` after STARTTLS unless
  `smtp.allow_insecure_auth` is set. Check the device trusts the proxy's
  certificate — with `smtp.tls.self_signed` it will not, until told to.

## The device authenticates but submissions are rejected

The proxy's rejections say why, and the same text is in its logs:

- **`550 5.7.1 this account may not send as …`** — the From header is not an
  address the account was granted. Link the mailbox to the account, add the
  address to its allowed senders, or set the account's sender policy to
  *rewrite* for devices whose From cannot be configured.
- **`535` from the proxy** — wrong username or password for the *SMTP
  account* (this is not the Microsoft 535). Reset the account's password; it
  is shown once.
- **`552`** — the message exceeds `storage.max_message_size`.

## Messages queue but never deliver

Open the queue in the admin interface; the last error on the message is the
upstream's own answer.

### `535 5.7.3 Authentication unsuccessful` (from Exchange)

The token was issued but Exchange refused it. In practice it is one of three
tenant settings, in this order of likelihood:

1. **`New-ServicePrincipal` used the wrong Object ID.** It must come from
   **Enterprise applications**, not App registrations. Delete and recreate:
   `Remove-ServicePrincipal`, then redo with the right ID.
2. **Admin consent was never granted** for `SMTP.SendAsApp`.
3. **`Add-MailboxPermission` was never run** for this mailbox.

**Credentials → Setup** in the admin interface prints the exact commands with
your values. The proxy deliberately keeps retrying these messages — the fix is
minutes of tenant work, and dropping the mail would make it worse.

### `AADSTS7000215` / `invalid_client`

The client secret is wrong or expired. Rotate it in Entra, then update the
credential; the change takes effect on the next delivery without a restart.

### `AADSTS90002: Tenant not found`

The tenant ID is wrong, or a sovereign-cloud tenant is using the worldwide
authority. Set the credential's Authority host.

### `4.7.500 Server busy`

The mailbox exceeded Exchange's 30 messages/minute. The proxy paces itself
below that, so seeing this usually means **something else** also submits as
the same mailbox (another tool, a stray script, a second proxy). Lower this
proxy's per-mailbox rate to leave room, or give the other sender its own
mailbox.

### `550 5.7.60 SendAsDenied`

The envelope sender did not match the mailbox and SendAs was not granted. The
proxy forces the envelope sender to the mailbox by default, so this points at
a manual configuration change; either revert it or run
`Add-RecipientPermission`.

## The connection test passes but mail still fails

The test acquires a token, which proves the Entra side (registration,
consent, secret). The Exchange side — service principal, mailbox permission —
is only exercised by an actual submission, because that is when Exchange
checks it. A passing test plus a failing delivery means step 5 of the setup.

## Admin interface

- **Locked out entirely** — create a new administrator from the host:
  `smtp-auth-proxy adduser --config … --username rescue`. It prints a
  password once.
- **Sign-in loops with single sign-on** — the redirect URI registered with
  the provider must be exactly `<admin.base_url>/api/v1/auth/oidc/callback`,
  and `admin.base_url` must be the origin the browser actually uses.
- **`sso_no_role` after signing in** — the provider authenticated you, but no
  claim matched `role_mappings` and no `default_role` is set. Check the
  provider actually sends the groups claim; many require it to be added to
  the token configuration explicitly.

## Reading the logs

Set `log.level: debug` for the full trace. Every message carries its queue ID
through submission, each delivery attempt and the final outcome, so grepping
one ID tells the whole story. Passwords, secrets and tokens never appear in
logs; if a pasted log contains one, it came from somewhere else.
