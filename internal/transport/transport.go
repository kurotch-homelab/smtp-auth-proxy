// Package transport delivers a queued message to Microsoft 365.
//
// Two backends implement the same interface: an SMTP relay that authenticates
// with SASL XOAUTH2, and the Microsoft Graph sendMail API. A mailbox chooses
// which one it uses.
package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Message is one delivery attempt's worth of state.
type Message struct {
	// ID is the queue identifier, for logging.
	ID string
	// Mailbox is the shared mailbox to send as. Its address goes in the XOAUTH2
	// "user=" field and in the envelope sender.
	Mailbox *store.Mailbox
	// Credential is the application registration that authenticates.
	Credential *store.OAuthCredential
	// Recipients are the envelope recipients.
	Recipients []string
	// Raw is the complete MIME message.
	Raw []byte
}

// EnvelopeFrom is the address used as the envelope sender.
//
// It is always the mailbox address rather than whatever the client asked for.
// Exchange Online requires the submitting identity to match the envelope sender
// unless the application has been granted SendAs on the other address, and a
// mismatch fails at delivery time with an error that is hard to read back to a
// configuration mistake.
func (m *Message) EnvelopeFrom() string { return m.Mailbox.Address }

// Transport delivers messages to Microsoft 365.
type Transport interface {
	// Name identifies the backend in logs and metrics.
	Name() string
	// Send delivers a message, or returns an *Error describing why it could not.
	Send(ctx context.Context, m *Message) error
}

// Error is a delivery failure, classified so the queue knows whether retrying
// can help.
type Error struct {
	// Code is the upstream's own status: an SMTP enhanced status like "4.7.500",
	// a bare SMTP code, or an HTTP status. It is what an operator matches
	// against Microsoft's documentation.
	Code string
	// Message is safe to store and show; it has been stripped of anything
	// secret.
	Message string
	// Permanent means retrying cannot help.
	Permanent bool
	// RetryAfter is a delay the upstream asked for, if it named one. Graph sets
	// this from its Retry-After header.
	RetryAfter time.Duration
	// Auth marks a failure to authenticate with Microsoft 365, which almost
	// always means a tenant setting is missing rather than anything about this
	// particular message.
	Auth bool
	// Err is the underlying cause, for logs.
	Err error
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// IsPermanent reports whether an error means the message will never be
// deliverable. Anything that is not explicitly permanent is retried: losing
// mail is worse than trying again.
func IsPermanent(err error) bool {
	var terr *Error
	if errors.As(err, &terr) {
		return terr.Permanent
	}
	return false
}

// RetryAfter returns the delay the upstream asked for, or zero.
func RetryAfter(err error) time.Duration {
	var terr *Error
	if errors.As(err, &terr) {
		return terr.RetryAfter
	}
	return 0
}

// AsFailure converts a delivery error into what the store records.
func AsFailure(err error) store.Failure {
	var terr *Error
	if errors.As(err, &terr) {
		return store.Failure{Code: terr.Code, Message: terr.Message, Permanent: terr.Permanent}
	}
	return store.Failure{Message: err.Error()}
}

// NewPermanent describes a failure that retrying cannot fix.
func NewPermanent(code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Permanent: true, Err: err}
}

// NewTransient describes a failure worth retrying.
func NewTransient(code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

// NewThrottled describes a failure where the upstream named a delay.
func NewThrottled(code, message string, retryAfter time.Duration, err error) *Error {
	return &Error{Code: code, Message: message, RetryAfter: retryAfter, Err: err}
}

// authFailureHint is appended to authentication errors, because a 535 from
// Exchange Online almost always means one of three specific tenant settings is
// missing and the operator has no other way to know which.
const authFailureHint = " — check that admin consent was granted for SMTP.SendAsApp, " +
	"that New-ServicePrincipal used the Object ID from Enterprise applications, " +
	"and that Add-MailboxPermission was run for this mailbox"

// NewAuthFailure describes an upstream authentication rejection.
//
// The SMTP code for one is 535, which is permanent, and treating it that way
// would fail every queued message the moment a secret expires or a permission
// is revoked. In practice these are configuration problems an operator fixes in
// minutes, and the entire point of the queue is not to lose mail in the
// meantime — so it is deliberately retried, and the admin interface surfaces it
// prominently instead.
func NewAuthFailure(code, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: strings.TrimSpace(message) + authFailureHint,
		// Not permanent: see above.
		Permanent: false,
		Auth:      true,
		Err:       err,
	}
}

// IsAuthFailure reports whether a delivery failed because Microsoft 365
// rejected the credential, which the dashboard raises separately from ordinary
// delivery problems.
func IsAuthFailure(err error) bool {
	var terr *Error
	return errors.As(err, &terr) && terr.Auth
}
