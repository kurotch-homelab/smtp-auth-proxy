package policy

import (
	"net"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

func mailbox(id, address string) *store.Mailbox {
	return &store.Mailbox{ID: id, Address: address, Enabled: true, Transport: store.TransportSMTP}
}

func account(policy store.FromPolicy) Account {
	return Account{ID: "acct", Username: "svc-printer", Enabled: true, Policy: policy}
}

func TestResolve(t *testing.T) {
	t.Parallel()

	sales := mailbox("mb-sales", "sales@example.com")
	support := mailbox("mb-support", "support@example.com")

	tests := []struct {
		name        string
		in          Input
		wantAction  Action
		wantMailbox string
		wantReason  string
	}{
		{
			name: "From matches a linked mailbox",
			in: Input{
				Account:    account(store.FromPolicyReject),
				Mailboxes:  []*store.Mailbox{sales, support},
				HeaderFrom: MustParseAddress("support@example.com"),
			},
			wantAction:  ActionAccept,
			wantMailbox: "support@example.com",
		},
		{
			name: "matching is case-insensitive",
			in: Input{
				Account:    account(store.FromPolicyReject),
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("Sales@EXAMPLE.com"),
			},
			wantAction:  ActionAccept,
			wantMailbox: "sales@example.com",
		},
		{
			name: "a display name does not affect the decision",
			in: Input{
				Account:    account(store.FromPolicyReject),
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress(`"Sales Team" <sales@example.com>`),
			},
			wantAction:  ActionAccept,
			wantMailbox: "sales@example.com",
		},
		{
			// The whole point of the package: an account must not be able to
			// send as a mailbox it was never linked to.
			name: "unlinked sender is rejected",
			in: Input{
				Account:    account(store.FromPolicyReject),
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("ceo@example.com"),
			},
			wantAction: ActionReject,
			wantReason: "may not send as ceo@example.com",
		},
		{
			name: "explicitly allowed sender goes out through the default mailbox",
			in: Input{
				Account: Account{
					ID: "acct", Username: "svc", Enabled: true,
					Policy:           store.FromPolicyReject,
					DefaultMailboxID: "mb-support",
					AllowedSenders:   []string{"noreply@example.com"},
				},
				Mailboxes:  []*store.Mailbox{sales, support},
				HeaderFrom: MustParseAddress("noreply@example.com"),
			},
			wantAction:  ActionAccept,
			wantMailbox: "support@example.com",
		},
		{
			name: "domain pattern in the allow-list",
			in: Input{
				Account: Account{
					ID: "acct", Username: "svc", Enabled: true,
					Policy:         store.FromPolicyReject,
					AllowedSenders: []string{"*@example.org"},
				},
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("anything@example.org"),
			},
			wantAction:  ActionAccept,
			wantMailbox: "sales@example.com",
		},
		{
			name: "rewrite policy replaces the sender",
			in: Input{
				Account:    account(store.FromPolicyRewrite),
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("printer@lan.local"),
			},
			wantAction:  ActionRewrite,
			wantMailbox: "sales@example.com",
		},
		{
			name: "passthrough policy leaves the sender alone",
			in: Input{
				Account:    account(store.FromPolicyPassthrough),
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("printer@lan.local"),
			},
			wantAction:  ActionAccept,
			wantMailbox: "sales@example.com",
		},
		{
			name: "no From header",
			in: Input{
				Account:   account(store.FromPolicyPassthrough),
				Mailboxes: []*store.Mailbox{sales},
			},
			wantAction: ActionReject,
			wantReason: "no From header",
		},
		{
			name: "disabled account",
			in: Input{
				Account:    Account{ID: "a", Username: "svc", Enabled: false, Policy: store.FromPolicyReject},
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("sales@example.com"),
			},
			wantAction: ActionReject,
			wantReason: "disabled",
		},
		{
			name: "account with no mailboxes",
			in: Input{
				Account:    account(store.FromPolicyReject),
				HeaderFrom: MustParseAddress("sales@example.com"),
			},
			wantAction: ActionReject,
			wantReason: "not linked to any mailbox",
		},
		{
			// A policy value this build does not understand means the binary is
			// older than the schema. Falling through to "allow" would turn a
			// rollout mistake into an open relay.
			name: "unknown policy fails closed",
			in: Input{
				Account:    account(store.FromPolicy("something-new")),
				Mailboxes:  []*store.Mailbox{sales},
				HeaderFrom: MustParseAddress("printer@lan.local"),
			},
			wantAction: ActionReject,
			wantReason: "not understood by this version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Resolve(tt.in)
			if got.Action != tt.wantAction {
				t.Fatalf("Action = %q, want %q (reason %q)", got.Action, tt.wantAction, got.Reason)
			}
			if tt.wantReason != "" && !strings.Contains(got.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to mention %q", got.Reason, tt.wantReason)
			}
			if tt.wantAction == ActionReject {
				if got.Mailbox != nil {
					t.Error("a rejection must not name a mailbox")
				}
				if got.Code < 400 || got.Enhanced == "" {
					t.Errorf("a rejection needs an SMTP status, got %d %q", got.Code, got.Enhanced)
				}
				return
			}
			if got.Mailbox == nil {
				t.Fatal("an accepted submission must name a mailbox")
			}
			if got.Mailbox.Address != tt.wantMailbox {
				t.Errorf("Mailbox = %q, want %q", got.Mailbox.Address, tt.wantMailbox)
			}
			if tt.wantAction == ActionRewrite && got.RewriteFrom != tt.wantMailbox {
				t.Errorf("RewriteFrom = %q, want %q", got.RewriteFrom, tt.wantMailbox)
			}
		})
	}
}

func TestResolveRejectsADisabledMailbox(t *testing.T) {
	t.Parallel()

	disabled := mailbox("mb", "sales@example.com")
	disabled.Enabled = false

	// Every path that selects a mailbox has to check this, not just the direct
	// match — otherwise disabling a mailbox would still let rewrite and
	// passthrough traffic through it.
	policies := []store.FromPolicy{
		store.FromPolicyReject, store.FromPolicyRewrite, store.FromPolicyPassthrough,
	}
	for _, p := range policies {
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()

			got := Resolve(Input{
				Account:    account(p),
				Mailboxes:  []*store.Mailbox{disabled},
				HeaderFrom: MustParseAddress("printer@lan.local"),
			})
			if !got.Rejected() {
				t.Errorf("Action = %q, want a rejection for a disabled mailbox", got.Action)
			}
		})
	}

	direct := Resolve(Input{
		Account:    account(store.FromPolicyReject),
		Mailboxes:  []*store.Mailbox{disabled},
		HeaderFrom: MustParseAddress("sales@example.com"),
	})
	if !direct.Rejected() || !strings.Contains(direct.Reason, "disabled") {
		t.Errorf("a direct match on a disabled mailbox = %+v, want a rejection", direct)
	}
}

func TestResolveDefaultMailboxSelection(t *testing.T) {
	t.Parallel()

	first := mailbox("mb-1", "one@example.com")
	second := mailbox("mb-2", "two@example.com")

	withDefault := Account{
		ID: "a", Username: "svc", Enabled: true,
		Policy: store.FromPolicyRewrite, DefaultMailboxID: "mb-2",
	}
	got := Resolve(Input{
		Account:    withDefault,
		Mailboxes:  []*store.Mailbox{first, second},
		HeaderFrom: MustParseAddress("printer@lan.local"),
	})
	if got.Mailbox.ID != "mb-2" {
		t.Errorf("Mailbox = %q, want the configured default", got.Mailbox.ID)
	}

	// With no default configured, the first linked mailbox is used rather than
	// rejecting: the account was granted it, so sending as it is authorized.
	noDefault := Account{ID: "a", Username: "svc", Enabled: true, Policy: store.FromPolicyRewrite}
	got = Resolve(Input{
		Account:    noDefault,
		Mailboxes:  []*store.Mailbox{first, second},
		HeaderFrom: MustParseAddress("printer@lan.local"),
	})
	if got.Mailbox.ID != "mb-1" {
		t.Errorf("Mailbox = %q, want the first linked mailbox", got.Mailbox.ID)
	}

	// A default that no longer exists must not select nothing.
	stale := Account{
		ID: "a", Username: "svc", Enabled: true,
		Policy: store.FromPolicyRewrite, DefaultMailboxID: "deleted",
	}
	got = Resolve(Input{
		Account:    stale,
		Mailboxes:  []*store.Mailbox{first},
		HeaderFrom: MustParseAddress("printer@lan.local"),
	})
	if got.Mailbox == nil || got.Mailbox.ID != "mb-1" {
		t.Errorf("Mailbox = %+v, want a fallback to the first mailbox", got.Mailbox)
	}
}

func TestResolvePreservesTheOriginalSender(t *testing.T) {
	t.Parallel()

	// A rewritten message keeps the original so it can go into Reply-To;
	// without it a reply would go to the shared mailbox instead of the device.
	got := Resolve(Input{
		Account:    account(store.FromPolicyRewrite),
		Mailboxes:  []*store.Mailbox{mailbox("mb", "sales@example.com")},
		HeaderFrom: MustParseAddress(`"Office Printer" <printer@lan.local>`),
	})
	if got.OriginalFrom.Normalized != "printer@lan.local" {
		t.Errorf("OriginalFrom = %q, want the address the client asked for", got.OriginalFrom.Normalized)
	}
	if got.OriginalFrom.Display != "Office Printer" {
		t.Errorf("OriginalFrom.Display = %q, want the display name preserved", got.OriginalFrom.Display)
	}
}

func TestRejectionListsWhatIsAllowed(t *testing.T) {
	t.Parallel()

	many := make([]*store.Mailbox, 8)
	for i := range many {
		many[i] = mailbox(string(rune('a'+i)), string(rune('a'+i))+"@example.com")
	}

	got := Resolve(Input{
		Account:    account(store.FromPolicyReject),
		Mailboxes:  many,
		HeaderFrom: MustParseAddress("nope@example.com"),
	})
	if !strings.Contains(got.Reason, "a@example.com") {
		t.Errorf("Reason = %q, want it to list what is allowed", got.Reason)
	}
	// The reason ends up in an SMTP response line, so a long list is truncated.
	if !strings.Contains(got.Reason, "more") {
		t.Errorf("Reason = %q, want a long list to be truncated", got.Reason)
	}
}

func TestCheckSourceAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cidrs   []string
		ip      string
		wantErr bool
	}{
		{name: "no restriction accepts anything", cidrs: nil, ip: "203.0.113.7"},
		{name: "inside the range", cidrs: []string{"10.0.0.0/8"}, ip: "10.1.2.3"},
		{name: "one of several ranges", cidrs: []string{"192.168.1.0/24", "10.0.0.0/8"}, ip: "10.1.2.3"},
		{name: "single host", cidrs: []string{"10.1.2.3/32"}, ip: "10.1.2.3"},
		{name: "IPv6", cidrs: []string{"2001:db8::/32"}, ip: "2001:db8::1"},

		{name: "outside every range", cidrs: []string{"10.0.0.0/8"}, ip: "192.168.1.1", wantErr: true},
		{name: "IPv4 against an IPv6 range", cidrs: []string{"2001:db8::/32"}, ip: "10.1.2.3", wantErr: true},
		// A malformed entry must not quietly widen access: the operator wrote a
		// restriction down, and skipping it would remove it.
		{name: "malformed CIDR", cidrs: []string{"not-a-cidr"}, ip: "10.1.2.3", wantErr: true},
		{name: "unknown client address", cidrs: []string{"10.0.0.0/8"}, ip: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := Account{Username: "svc", AllowCIDRs: tt.cidrs}
			err := CheckSourceAddress(a, net.ParseIP(tt.ip))
			if tt.wantErr && err == nil {
				t.Errorf("CheckSourceAddress(%v, %q) = nil, want an error", tt.cidrs, tt.ip)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckSourceAddress(%v, %q) = %v, want nil", tt.cidrs, tt.ip, err)
			}
		})
	}
}

func TestAccountFromStore(t *testing.T) {
	t.Parallel()

	stored := &store.SMTPAccount{
		ID:               "acct",
		Username:         "svc-printer",
		Enabled:          true,
		FromPolicy:       store.FromPolicyRewrite,
		DefaultMailboxID: store.NullString("mb-1"),
		AllowCIDRs:       []string{"10.0.0.0/8"},
	}
	allowed := []*store.AllowedSender{
		{Pattern: "noreply@example.com"},
		{Pattern: "*@example.org"},
	}

	got := AccountFromStore(stored, allowed)
	if got.DefaultMailboxID != "mb-1" {
		t.Errorf("DefaultMailboxID = %q, want mb-1", got.DefaultMailboxID)
	}
	if len(got.AllowedSenders) != 2 || got.AllowedSenders[1] != "*@example.org" {
		t.Errorf("AllowedSenders = %v, want both patterns", got.AllowedSenders)
	}
	if got.Policy != store.FromPolicyRewrite || !got.Enabled {
		t.Errorf("AccountFromStore = %+v, want the stored policy and enabled state", got)
	}

	// A NULL default must become the empty string, not "<nil>".
	stored.DefaultMailboxID = store.NullString("")
	if got := AccountFromStore(stored, nil); got.DefaultMailboxID != "" {
		t.Errorf("DefaultMailboxID = %q, want empty for a NULL default", got.DefaultMailboxID)
	}
}
