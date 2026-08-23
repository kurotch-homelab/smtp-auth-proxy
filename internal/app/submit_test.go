package app

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func TestSubmitQueuesTheMessage(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	account, mb := seedAccount(t, db, nil)
	s := &submitter{db: db, log: discardLogger()}

	raw := []byte("From: sales@example.com\r\nTo: ops@example.net\r\n\r\nbody")
	id, err := s.Submit(t.Context(), &smtpsrv.Submission{
		Identity:     &smtpsrv.Identity{AccountID: account.ID, Username: account.Username},
		Mailbox:      mb,
		EnvelopeFrom: policy.MustParseAddress("printer@lan.local"),
		HeaderFrom:   policy.MustParseAddress("sales@example.com"),
		Recipients:   []string{"ops@example.net"},
		Raw:          raw,
		Subject:      "Scan complete",
		MessageID:    "abc@lan.local",
		ClientIP:     net.ParseIP("10.0.0.5"),
		ReceivedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if id == "" {
		t.Fatal("Submit returned no queue id")
	}

	m, err := db.Messages().Get(t.Context(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m.Status != store.StatusQueued {
		t.Errorf("Status = %q, want queued", m.Status)
	}
	// The username and address are denormalized so the history survives a
	// deletion of either.
	if m.AccountUsername != account.Username || m.MailboxAddress != mb.Address {
		t.Errorf("denormalized fields = %q/%q", m.AccountUsername, m.MailboxAddress)
	}
	// The envelope sender is kept as the client asked for it; delivery forces
	// it to the mailbox, and the difference is the audit trail.
	if m.EnvelopeFrom != "printer@lan.local" {
		t.Errorf("EnvelopeFrom = %q, want what the client sent", m.EnvelopeFrom)
	}
	if m.ClientIP != "10.0.0.5" {
		t.Errorf("ClientIP = %q", m.ClientIP)
	}
	if m.SizeBytes != int64(len(raw)) {
		t.Errorf("SizeBytes = %d, want %d", m.SizeBytes, len(raw))
	}

	body, err := db.Messages().Body(t.Context(), id)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if !bytes.Equal(body, raw) {
		t.Errorf("the stored body differs from the submission")
	}
}

func TestSubmitWithoutAClientAddress(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	account, mb := seedAccount(t, db, nil)
	s := &submitter{db: db, log: discardLogger()}

	// A connection over a Unix socket has no IP; that must not fail the
	// submission or store the string "<nil>".
	id, err := s.Submit(t.Context(), &smtpsrv.Submission{
		Identity:   &smtpsrv.Identity{AccountID: account.ID, Username: account.Username},
		Mailbox:    mb,
		HeaderFrom: policy.MustParseAddress("sales@example.com"),
		Recipients: []string{"ops@example.net"},
		Raw:        []byte("From: sales@example.com\r\n\r\nbody"),
		ReceivedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	m, err := db.Messages().Get(t.Context(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m.ClientIP != "" {
		t.Errorf("ClientIP = %q, want empty", m.ClientIP)
	}
}
