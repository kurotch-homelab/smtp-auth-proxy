package transport

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

func TestEnvelopeFromIsAlwaysTheMailbox(t *testing.T) {
	t.Parallel()

	m := &Message{Mailbox: &store.Mailbox{Address: "shared@example.com"}}
	// Exchange Online requires the submitting identity to match the envelope
	// sender unless SendAs was granted, so this must never be the address the
	// client asked for.
	if got := m.EnvelopeFrom(); got != "shared@example.com" {
		t.Errorf("EnvelopeFrom() = %q, want the mailbox address", got)
	}
}

func TestErrorFormatting(t *testing.T) {
	t.Parallel()

	withCode := NewPermanent("5.1.1", "User unknown", nil)
	if got := withCode.Error(); got != "5.1.1: User unknown" {
		t.Errorf("Error() = %q", got)
	}

	withoutCode := NewTransient("", "connection reset", nil)
	if got := withoutCode.Error(); got != "connection reset" {
		t.Errorf("Error() = %q", got)
	}
}

func TestErrorUnwrapsTheCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("dial tcp: connection refused")
	err := NewTransient("net", "could not connect", cause)

	if !errors.Is(err, cause) {
		t.Error("the underlying cause is not reachable through errors.Is")
	}
}

func TestIsPermanent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "permanent", err: NewPermanent("5.1.1", "User unknown", nil), want: true},
		{name: "transient", err: NewTransient("4.3.2", "Try later", nil)},
		// An authentication failure is deliberately retried: it is nearly
		// always a tenant setting an operator can fix, and the queue exists so
		// that mail is not lost while they do.
		{name: "authentication failure", err: NewAuthFailure("5.7.3", "Authentication unsuccessful", nil)},
		{name: "throttled", err: NewThrottled("429", "Too many requests", time.Minute, nil)},
		// Anything not explicitly permanent is retried: losing mail is worse
		// than trying again.
		{name: "plain error", err: errors.New("something went wrong")},
		{name: "wrapped permanent", err: fmt.Errorf("delivering: %w", NewPermanent("550", "denied", nil)), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsPermanent(tt.err); got != tt.want {
				t.Errorf("IsPermanent(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsAuthFailure(t *testing.T) {
	t.Parallel()

	if !IsAuthFailure(NewAuthFailure("5.7.3", "Authentication unsuccessful", nil)) {
		t.Error("IsAuthFailure = false for an authentication failure")
	}
	if IsAuthFailure(NewTransient("4.3.2", "Try later", nil)) {
		t.Error("IsAuthFailure = true for an ordinary transient failure")
	}
	if IsAuthFailure(errors.New("plain")) {
		t.Error("IsAuthFailure = true for a plain error")
	}
}

func TestAuthFailureNamesTheThreeTenantSteps(t *testing.T) {
	t.Parallel()

	// "535 5.7.3 Authentication unsuccessful" on its own tells an operator
	// nothing about which of the three setup steps was missed.
	err := NewAuthFailure("5.7.3", "Authentication unsuccessful", nil)
	for _, want := range []string{"SMTP.SendAsApp", "New-ServicePrincipal", "Add-MailboxPermission"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not mention %s: %v", want, err)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	if got := RetryAfter(NewThrottled("429", "Too many requests", 90*time.Second, nil)); got != 90*time.Second {
		t.Errorf("RetryAfter = %v, want 90s", got)
	}
	if got := RetryAfter(NewTransient("4.3.2", "Try later", nil)); got != 0 {
		t.Errorf("RetryAfter = %v, want 0 when the upstream named no delay", got)
	}
	if got := RetryAfter(errors.New("plain")); got != 0 {
		t.Errorf("RetryAfter = %v, want 0", got)
	}
}

func TestAsFailure(t *testing.T) {
	t.Parallel()

	got := AsFailure(NewPermanent("5.1.1", "User unknown", nil))
	if got.Code != "5.1.1" || got.Message != "User unknown" || !got.Permanent {
		t.Errorf("AsFailure = %+v", got)
	}

	// A plain error still has to be recordable, or a delivery failure the
	// backend did not classify would be stored with no explanation at all.
	plain := AsFailure(errors.New("something went wrong"))
	if plain.Message != "something went wrong" || plain.Permanent {
		t.Errorf("AsFailure(plain) = %+v", plain)
	}
}
