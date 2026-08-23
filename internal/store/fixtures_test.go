package store_test

import (
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// newCredential inserts a credential and returns it.
func newCredential(t *testing.T, db *store.DB, name string) *store.OAuthCredential {
	t.Helper()

	c := &store.OAuthCredential{
		Name:            name,
		TenantID:        "11111111-1111-1111-1111-111111111111",
		ClientID:        "22222222-2222-2222-2222-222222222222",
		AuthType:        store.AuthTypeSecret,
		ClientSecretEnc: "v1.k1.sealed",
		AuthorityHost:   "https://login.microsoftonline.com",
	}
	if err := db.Credentials().Create(t.Context(), c); err != nil {
		t.Fatalf("creating credential %q: %v", name, err)
	}
	return c
}

// newMailbox inserts a mailbox backed by a fresh credential.
func newMailbox(t *testing.T, db *store.DB, address string) *store.Mailbox {
	t.Helper()

	c := newCredential(t, db, "cred-for-"+address)
	m := &store.Mailbox{
		Address:           address,
		DisplayName:       address,
		OAuthCredentialID: c.ID,
		Transport:         store.TransportSMTP,
		Enabled:           true,
	}
	if err := db.Mailboxes().Create(t.Context(), m); err != nil {
		t.Fatalf("creating mailbox %q: %v", address, err)
	}
	return m
}

// newAccount inserts an SMTP account.
func newAccount(t *testing.T, db *store.DB, username string) *store.SMTPAccount {
	t.Helper()

	a := &store.SMTPAccount{
		Username:     username,
		PasswordHash: "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg",
		FromPolicy:   store.FromPolicyReject,
		Enabled:      true,
	}
	if err := db.Accounts().Create(t.Context(), a); err != nil {
		t.Fatalf("creating account %q: %v", username, err)
	}
	return a
}

// enqueue stores a queued message ready for immediate delivery.
func enqueue(t *testing.T, db *store.DB, mailbox *store.Mailbox, to string) *store.Message {
	t.Helper()

	m := &store.Message{
		MailboxID:      store.NullString(mailbox.ID),
		MailboxAddress: mailbox.Address,
		EnvelopeFrom:   mailbox.Address,
		HeaderFrom:     mailbox.Address,
		Recipients:     []string{to},
		SizeBytes:      42,
		NextAttemptAt:  time.Now().UTC().Add(-time.Second),
	}
	if err := db.Messages().Enqueue(t.Context(), m, []byte("Subject: test\r\n\r\nbody")); err != nil {
		t.Fatalf("enqueueing a message to %q: %v", to, err)
	}
	return m
}
