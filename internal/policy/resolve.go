package policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Action is what to do with a submission.
type Action string

// Decision outcomes.
const (
	// ActionAccept sends the message as-is.
	ActionAccept Action = "accept"
	// ActionRewrite sends it after replacing the From header.
	ActionRewrite Action = "rewrite"
	// ActionReject refuses it.
	ActionReject Action = "reject"
)

// Decision is the outcome of evaluating one submission.
type Decision struct {
	Action Action
	// Mailbox is the shared mailbox the message will be sent as. It is nil only
	// when Action is ActionReject.
	Mailbox *store.Mailbox
	// RewriteFrom is the address to put in the From header, set only for
	// ActionRewrite.
	RewriteFrom string
	// OriginalFrom is the sender the client asked for, preserved so a rewritten
	// message can carry it in Reply-To.
	OriginalFrom Address

	// Code and Enhanced are the SMTP status to return on a rejection.
	Code     int
	Enhanced string
	// Reason is safe to show the client and to log.
	Reason string
}

// Rejected reports whether the submission was refused.
func (d Decision) Rejected() bool { return d.Action == ActionReject }

// Account is the subset of an SMTP account this package needs.
type Account struct {
	ID       string
	Username string
	Enabled  bool
	Policy   store.FromPolicy
	// DefaultMailboxID is used when the From header matches no mailbox.
	DefaultMailboxID string
	// AllowedSenders are extra From patterns beyond the mailbox addresses.
	AllowedSenders []string
	// AllowCIDRs restricts where the account may connect from. Empty means any.
	AllowCIDRs []string
}

// Input is one submission to evaluate.
type Input struct {
	Account Account
	// Mailboxes are the mailboxes this account may send as.
	Mailboxes []*store.Mailbox
	// EnvelopeFrom is the MAIL FROM path. It may be empty for a bounce.
	EnvelopeFrom Address
	// HeaderFrom is the From header. It is what recipients see, so it is what
	// the policy is enforced against.
	HeaderFrom Address
}

// Resolve decides whether a submission may be sent and as which mailbox.
//
// The From *header* drives the decision, not the envelope sender: the header is
// what a recipient sees and what an impersonation attempt would forge. The
// envelope sender is then forced to the resolved mailbox at delivery time,
// because Exchange Online requires the submitting identity to match unless the
// application has been granted SendAs on the other address.
func Resolve(in Input) Decision {
	if !in.Account.Enabled {
		return reject(550, "5.7.1", "this account is disabled")
	}
	if len(in.Mailboxes) == 0 {
		return reject(550, "5.7.1",
			"this account is not linked to any mailbox; grant it one in the admin interface")
	}

	// A message with no From header has no identity to check. Exchange would
	// reject it anyway, so refuse it here where the reason can be explained.
	if in.HeaderFrom.IsEmpty() {
		return reject(550, "5.7.1", "the message has no From header")
	}

	if mb := matchMailbox(in.Mailboxes, in.HeaderFrom.Normalized); mb != nil {
		if !mb.Enabled {
			return reject(550, "5.7.1", fmt.Sprintf("the mailbox %s is disabled", mb.Address))
		}
		return Decision{Action: ActionAccept, Mailbox: mb, OriginalFrom: in.HeaderFrom}
	}

	// The From address is not one of the account's mailboxes. It may still be
	// explicitly allowed, in which case it goes out through the default mailbox
	// and Exchange decides whether the SendAs permission exists.
	if matchesAny(in.HeaderFrom.Normalized, in.Account.AllowedSenders) {
		mb := defaultMailbox(in.Mailboxes, in.Account.DefaultMailboxID)
		if !mb.Enabled {
			return reject(550, "5.7.1", fmt.Sprintf("the mailbox %s is disabled", mb.Address))
		}
		return Decision{Action: ActionAccept, Mailbox: mb, OriginalFrom: in.HeaderFrom}
	}

	return applyFromPolicy(in)
}

func applyFromPolicy(in Input) Decision {
	mb := defaultMailbox(in.Mailboxes, in.Account.DefaultMailboxID)

	switch in.Account.Policy {
	case store.FromPolicyRewrite:
		if !mb.Enabled {
			return reject(550, "5.7.1", fmt.Sprintf("the mailbox %s is disabled", mb.Address))
		}
		return Decision{
			Action:       ActionRewrite,
			Mailbox:      mb,
			RewriteFrom:  mb.Address,
			OriginalFrom: in.HeaderFrom,
		}

	case store.FromPolicyPassthrough:
		if !mb.Enabled {
			return reject(550, "5.7.1", fmt.Sprintf("the mailbox %s is disabled", mb.Address))
		}
		return Decision{Action: ActionAccept, Mailbox: mb, OriginalFrom: in.HeaderFrom}

	case store.FromPolicyReject:
		return reject(550, "5.7.1", fmt.Sprintf(
			"this account may not send as %s; allowed senders are: %s",
			in.HeaderFrom.Original, describeAllowed(in.Mailboxes, in.Account.AllowedSenders)))

	default:
		// An unknown policy must not fall through to "allow". A value the
		// database accepted but this build does not understand means the binary
		// is older than the schema.
		return reject(451, "4.3.5", fmt.Sprintf(
			"the sender policy %q is not understood by this version", in.Account.Policy))
	}
}

// matchMailbox finds the mailbox whose address equals the given address.
func matchMailbox(mailboxes []*store.Mailbox, normalized string) *store.Mailbox {
	for _, mb := range mailboxes {
		if strings.EqualFold(mb.Address, normalized) {
			return mb
		}
	}
	return nil
}

// defaultMailbox returns the account's configured default, or the first mailbox
// it may use. Callers only reach this with a non-empty list.
func defaultMailbox(mailboxes []*store.Mailbox, defaultID string) *store.Mailbox {
	if defaultID != "" {
		for _, mb := range mailboxes {
			if mb.ID == defaultID {
				return mb
			}
		}
	}
	return mailboxes[0]
}

func matchesAny(normalized string, patterns []string) bool {
	for _, p := range patterns {
		if MatchesPattern(normalized, p) {
			return true
		}
	}
	return false
}

// describeAllowed renders what the account may send as, for a rejection message
// an operator can act on without opening the admin UI.
func describeAllowed(mailboxes []*store.Mailbox, patterns []string) string {
	parts := make([]string, 0, len(mailboxes)+len(patterns))
	for _, mb := range mailboxes {
		parts = append(parts, mb.Address)
	}
	parts = append(parts, patterns...)

	const maxListed = 5
	if len(parts) > maxListed {
		return strings.Join(parts[:maxListed], ", ") +
			fmt.Sprintf(" and %d more", len(parts)-maxListed)
	}
	return strings.Join(parts, ", ")
}

func reject(code int, enhanced, reason string) Decision {
	return Decision{Action: ActionReject, Code: code, Enhanced: enhanced, Reason: reason}
}

// CheckSourceAddress reports whether an account may connect from an address.
//
// An empty CIDR list means any source is accepted; that is the default, because
// most homelab deployments have one flat network and would otherwise have to
// maintain a list that adds nothing.
func CheckSourceAddress(account Account, ip net.IP) error {
	if len(account.AllowCIDRs) == 0 {
		return nil
	}
	if ip == nil {
		return fmt.Errorf("policy: account %s restricts source addresses, but the client address is unknown", account.Username)
	}

	for _, raw := range account.AllowCIDRs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			// A malformed CIDR must not silently widen access. Skipping it would
			// be the same as removing a restriction the operator wrote down.
			return fmt.Errorf("policy: account %s has an invalid allowed network %q: %w",
				account.Username, raw, err)
		}
		if network.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("policy: account %s is not allowed to connect from %s", account.Username, ip)
}

// AccountFromStore adapts a stored account and its allowed senders.
func AccountFromStore(a *store.SMTPAccount, allowed []*store.AllowedSender) Account {
	patterns := make([]string, 0, len(allowed))
	for _, s := range allowed {
		patterns = append(patterns, s.Pattern)
	}
	return Account{
		ID:               a.ID,
		Username:         a.Username,
		Enabled:          a.Enabled,
		Policy:           a.FromPolicy,
		DefaultMailboxID: a.DefaultMailboxID.String,
		AllowedSenders:   patterns,
		AllowCIDRs:       a.AllowCIDRs,
	}
}
