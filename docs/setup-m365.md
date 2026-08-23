# Setting up Microsoft 365

The proxy authenticates to Exchange Online as a Microsoft Entra **application**,
using the OAuth 2.0 client credentials flow. Three things have to be true in the
tenant before Exchange will accept it, and none of them can be worked out from
the error it returns when they are not. This page walks through all three.

You need a **tenant administrator** for steps 2–4, and an **Exchange
administrator** for step 5. The whole thing takes about fifteen minutes.

## 1. Decide which mailboxes will send

Each LAN service sends *as* an Exchange Online mailbox — typically a shared
mailbox such as `scanner@example.com` or `alerts@example.com`. Shared mailboxes
need no license as long as they stay under 50 GB, which makes them the natural
fit. Create them first (Microsoft 365 admin center → Teams & groups → Shared
mailboxes).

One application registration can send as **every** mailbox you grant it, so you
only do the registration once, however many mailboxes you add later.

## 2. Register the application

In [Microsoft Entra admin center](https://entra.microsoft.com) →
**Identity → Applications → App registrations → New registration**:

- **Name**: `smtp-auth-proxy` (anything recognisable)
- **Supported account types**: *Accounts in this organizational directory only*
- **Redirect URI**: leave empty — this flow never redirects anyone

From the registration's **Overview** page, note two values for later:

- **Application (client) ID**
- **Directory (tenant) ID**

## 3. Grant the permission

Still in the registration: **API permissions → Add a permission → APIs my
organization uses** → search for **Office 365 Exchange Online** →
**Application permissions** → tick **`SMTP.SendAsApp`** → **Add permissions**.

> Using the Graph transport instead of SMTP? Grant **Microsoft Graph →
> Application permissions → `Mail.Send`** as well (or instead).

Then press **Grant admin consent for &lt;tenant&gt;**. Without consent, Entra
still issues tokens — and Exchange refuses every one of them with
`535 5.7.3 Authentication unsuccessful`, which is the least helpful error in
this whole setup.

## 4. Create a client secret (or certificate)

**Certificates & secrets → New client secret.** Copy the **Value** immediately;
it is shown once.

Note the expiry date, and enter it in the proxy's credential form: the
dashboard warns 30 days ahead, because a quietly expiring secret is the most
common way a working deployment stops.

For longer-lived deployments, a certificate (public key uploaded here, private
key given to the proxy) avoids the periodic secret rotation.

## 5. Register the service principal in Exchange

This is the step everyone gets wrong, in the same way.

Open **Identity → Applications → Enterprise applications** (⚠️ *not App
registrations*), find the application, and copy its **Object ID**. The Object
ID under App registrations is a **different value**, and using it produces a
535 with everything else configured perfectly.

Then, in Exchange Online PowerShell:

```powershell
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -Organization <tenant-id>

New-ServicePrincipal -AppId <application-client-id> -ObjectId <enterprise-app-object-id> `
  -DisplayName "smtp-auth-proxy"

$sp = Get-ServicePrincipal -Identity "smtp-auth-proxy"

# Once per mailbox the proxy may send as:
Add-MailboxPermission -Identity "scanner@example.com" -User $sp.Identity -AccessRights FullAccess
```

> The proxy's admin interface generates exactly these commands with your values
> filled in: **Credentials → Setup**.

`Add-RecipientPermission ... -AccessRights SendAs` is only needed if a
message's envelope sender will differ from the mailbox itself. The proxy forces
the envelope sender to the mailbox address by default precisely so you do not
need it.

## 6. Configure the proxy

In the admin interface:

1. **Credentials → New credential** — the tenant ID, client ID and secret from
   steps 2 and 4.
2. **Mailboxes → New mailbox** — the address from step 1, on that credential.
3. Press **Test** on the mailbox. It acquires a real token from Entra, which
   verifies steps 2–4. (Step 5 can only be verified by sending mail: Exchange
   checks the mailbox permission at submission time.)
4. **SMTP accounts → New account** — one per device, linked to the mailbox.
   The generated password is shown once; configure the device with it.

Point the device at the proxy: server = the proxy's address, port 587,
STARTTLS, the account's username and password.

## Sovereign clouds

GCC High, DoD and 21Vianet tenants use different endpoints. Set them in
`config.yaml` under `upstream`, and per credential (**Authority host**) where a
single proxy serves tenants in different clouds. Instance discovery is
disabled automatically for a non-default authority.

## Limits worth knowing

Exchange Online caps SMTP client submission per mailbox at **30 messages a
minute**, **3 concurrent connections** and **10,000 recipients a day**. The
proxy paces itself below the first two and refuses configuration that exceeds
them. The Graph transport is not subject to the SMTP limits, but caps a single
message at 4 MB and always leaves a copy in Sent Items.
