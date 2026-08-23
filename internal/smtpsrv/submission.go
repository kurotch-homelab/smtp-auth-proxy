package smtpsrv

import (
	"context"
	"net"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Submission is a message that passed authentication and the sender policy,
// ready to be queued for delivery.
type Submission struct {
	Identity *Identity
	// Mailbox is the shared mailbox this will be sent as.
	Mailbox *store.Mailbox

	// EnvelopeFrom is what the client asked for. Delivery forces the envelope
	// sender to the mailbox address, because Exchange Online requires the
	// submitting identity to match unless SendAs has been granted separately;
	// this is kept for the audit trail.
	EnvelopeFrom policy.Address
	// HeaderFrom is the From header after any rewrite.
	HeaderFrom policy.Address
	Recipients []string

	// Raw is the complete message, headers included, as it will be sent.
	Raw []byte
	// Subject and MessageID are extracted for the queue view. Subject is only
	// populated when the operator has opted into recording it.
	Subject   string
	MessageID string

	ClientIP   net.IP
	ClientHelo string
	// TLS reports whether the client's connection was encrypted, for the
	// Received header and the audit trail.
	TLS        bool
	ReceivedAt time.Time
}

// Submitter accepts a validated submission for delivery.
type Submitter interface {
	// Submit persists the message and returns the queue ID reported to the
	// client in the 250 response.
	Submit(ctx context.Context, sub *Submission) (string, error)
}
