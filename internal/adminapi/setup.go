package adminapi

import (
	"fmt"
	"strings"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// buildSetup generates the tenant configuration an operator has to apply.
//
// Three things have to be true before Exchange Online will accept a token, and
// none of them can be discovered from the error it returns when they are not:
// admin consent for SMTP.SendAsApp, a service principal registered with the
// Object ID from *Enterprise applications* (not App registrations), and a
// mailbox permission per mailbox. Generating the commands with the credential's
// own values removes the guesswork and the most common mistake.
func buildSetup(c *store.OAuthCredential, mailboxAddresses []string) setupResponse {
	steps := []string{
		"In Microsoft Entra ID, open this application's API permissions and add the " +
			"application permission SMTP.SendAsApp under \"Office 365 Exchange Online\".",
		"Grant admin consent for that permission. Without consent the token is issued but " +
			"Exchange refuses it with 535 5.7.3.",
		"Copy the Object ID from the Enterprise applications page — not from App registrations. " +
			"Using the wrong one is the single most common cause of a 535 with everything else correct.",
		"Run the PowerShell below as an Exchange administrator.",
	}
	if len(mailboxAddresses) == 0 {
		steps = append(steps, "Add a mailbox to this credential, then run Add-MailboxPermission for it.")
	}

	var b strings.Builder
	b.WriteString("# Run in Exchange Online PowerShell, as an Exchange administrator.\n")
	b.WriteString("Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser\n")
	b.WriteString("Import-Module ExchangeOnlineManagement\n")
	fmt.Fprintf(&b, "Connect-ExchangeOnline -Organization %s\n\n", c.TenantID)

	b.WriteString("# The Object ID below must come from Entra ID > Enterprise applications,\n")
	b.WriteString("# NOT from App registrations. They are different values.\n")
	b.WriteString("$objectId = \"<Object ID from Enterprise applications>\"\n\n")

	fmt.Fprintf(&b, "New-ServicePrincipal -AppId %s -ObjectId $objectId `\n", c.ClientID)
	fmt.Fprintf(&b, "  -DisplayName \"smtp-auth-proxy (%s)\"\n\n", c.Name)

	fmt.Fprintf(&b, "$sp = Get-ServicePrincipal -Identity \"smtp-auth-proxy (%s)\"\n\n", c.Name)

	if len(mailboxAddresses) == 0 {
		b.WriteString("# Once a mailbox is added to this credential, grant access to it:\n")
		b.WriteString("# Add-MailboxPermission -Identity \"shared@example.com\" -User $sp.Identity -AccessRights FullAccess\n")
	} else {
		b.WriteString("# Grant access to each mailbox this credential sends as.\n")
		for _, address := range mailboxAddresses {
			fmt.Fprintf(&b,
				"Add-MailboxPermission -Identity %q -User $sp.Identity -AccessRights FullAccess\n",
				address)
		}
		b.WriteString("\n# Only needed if a message's envelope sender differs from the mailbox:\n")
		for _, address := range mailboxAddresses {
			fmt.Fprintf(&b,
				"# Add-RecipientPermission -Identity %q -Trustee $sp.Identity -AccessRights SendAs\n",
				address)
		}
	}

	fmt.Fprintf(&b, "\n# The proxy requests tokens for the scope %s\n", oauthScopeForSetup)

	return setupResponse{
		Summary: fmt.Sprintf(
			"Exchange Online needs three things before it will accept this credential: "+
				"admin consent for SMTP.SendAsApp, a registered service principal, and a mailbox "+
				"permission for each of the %d mailbox(es) it sends as.", len(mailboxAddresses)),
		Steps:    steps,
		Commands: b.String(),
		Docs:     "https://learn.microsoft.com/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth",
	}
}
