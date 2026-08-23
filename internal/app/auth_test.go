package app

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

const testPassword = "device-password"

// seedAccount creates a mailbox and an account that may send as it.
func seedAccount(t *testing.T, db *store.DB, mutate func(*store.SMTPAccount)) (*store.SMTPAccount, *store.Mailbox) {
	t.Helper()

	cred := &store.OAuthCredential{
		Name: "primary", TenantID: "tenant", ClientID: "client",
		AuthType: store.AuthTypeSecret, ClientSecretEnc: "v1.k1.sealed",
	}
	if err := db.Credentials().Create(t.Context(), cred); err != nil {
		t.Fatalf("creating a credential: %v", err)
	}

	mb := &store.Mailbox{
		Address: "sales@example.com", OAuthCredentialID: cred.ID,
		Transport: store.TransportSMTP, Enabled: true,
	}
	if err := db.Mailboxes().Create(t.Context(), mb); err != nil {
		t.Fatalf("creating a mailbox: %v", err)
	}

	hash, err := appcrypto.HashPasswordWith(testPassword, cheapParams())
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	account := &store.SMTPAccount{
		Username: "svc-printer", PasswordHash: hash,
		DefaultMailboxID: store.NullString(mb.ID),
		FromPolicy:       store.FromPolicyReject, Enabled: true,
	}
	if mutate != nil {
		mutate(account)
	}
	if err := db.Accounts().Create(t.Context(), account); err != nil {
		t.Fatalf("creating an account: %v", err)
	}
	if err := db.Accounts().SetMailboxes(t.Context(), account.ID, []string{mb.ID}); err != nil {
		t.Fatalf("linking the mailbox: %v", err)
	}
	return account, mb
}

// discardLogger throws away the proxy's logs; these tests assert on behavior,
// not on what was written.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// cheapParams keep the tests fast.
func cheapParams() appcrypto.Argon2Params {
	return appcrypto.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func newAuthenticator(t *testing.T) (*authenticator, *store.DB) {
	t.Helper()

	db := storetest.Open(t, store.DriverSQLite)
	return &authenticator{db: db, log: discardLogger()}, db
}

func TestAuthenticateAcceptsValidCredentials(t *testing.T) {
	t.Parallel()

	a, db := newAuthenticator(t)
	account, mb := seedAccount(t, db, nil)

	identity, err := a.Authenticate(t.Context(), account.Username, testPassword, net.ParseIP("10.0.0.5"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.AccountID != account.ID || identity.Username != account.Username {
		t.Errorf("identity = %+v", identity)
	}
	if len(identity.Mailboxes) != 1 || identity.Mailboxes[0].ID != mb.ID {
		t.Errorf("mailboxes = %+v, want the linked one", identity.Mailboxes)
	}
	if identity.Account.Policy != store.FromPolicyReject {
		t.Errorf("policy = %q", identity.Account.Policy)
	}
}

func TestAuthenticateRecordsLastUse(t *testing.T) {
	t.Parallel()

	a, db := newAuthenticator(t)
	account, _ := seedAccount(t, db, nil)

	if _, err := a.Authenticate(t.Context(), account.Username, testPassword, nil); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	got, err := db.Accounts().Get(t.Context(), account.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastUsedAt.Valid {
		t.Error("last use was not recorded")
	}
	if time.Since(got.LastUsedAt.Time) > time.Minute {
		t.Errorf("LastUsedAt = %v, want about now", got.LastUsedAt.Time)
	}
}

func TestAuthenticateRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*store.SMTPAccount)
		username string
		password string
		remote   net.IP
	}{
		{name: "unknown username", username: "nobody", password: testPassword},
		{name: "wrong password", username: "svc-printer", password: "wrong"},
		{name: "empty password", username: "svc-printer", password: ""},
		{
			name:     "disabled account",
			mutate:   func(a *store.SMTPAccount) { a.Enabled = false },
			username: "svc-printer", password: testPassword,
		},
		{
			name:     "source address outside the allowed networks",
			mutate:   func(a *store.SMTPAccount) { a.AllowCIDRs = []string{"10.0.0.0/8"} },
			username: "svc-printer", password: testPassword,
			remote: net.ParseIP("192.168.1.5"),
		},
		{
			name:     "restricted account with an unknown source address",
			mutate:   func(a *store.SMTPAccount) { a.AllowCIDRs = []string{"10.0.0.0/8"} },
			username: "svc-printer", password: testPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, db := newAuthenticator(t)
			seedAccount(t, db, tt.mutate)

			_, err := a.Authenticate(t.Context(), tt.username, tt.password, tt.remote)
			if err == nil {
				t.Fatal("Authenticate succeeded")
			}
			// Every failure reaches the SMTP layer as the same error, so the
			// client cannot tell which check failed.
			if !errors.Is(err, smtpsrv.ErrAuthFailed) {
				t.Errorf("Authenticate = %v, want ErrAuthFailed", err)
			}
		})
	}
}

func TestAuthenticateAllowsARestrictedAccountFromItsNetwork(t *testing.T) {
	t.Parallel()

	a, db := newAuthenticator(t)
	seedAccount(t, db, func(acc *store.SMTPAccount) {
		acc.AllowCIDRs = []string{"10.0.0.0/8", "192.168.1.0/24"}
	})

	if _, err := a.Authenticate(t.Context(), "svc-printer", testPassword, net.ParseIP("192.168.1.42")); err != nil {
		t.Errorf("Authenticate from an allowed network: %v", err)
	}
}

// An unknown username must cost the same as a known one, or the SMTP port
// becomes a way to enumerate every service account on the network.
func TestAuthenticateSpendsTheSameEffortOnAnUnknownUsername(t *testing.T) {
	t.Parallel()

	a, db := newAuthenticator(t)
	// Real hashing parameters, so the comparison is meaningful.
	hash, err := appcrypto.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	seedAccount(t, db, func(acc *store.SMTPAccount) { acc.PasswordHash = hash })

	measure := func(username string) time.Duration {
		start := time.Now()
		_, _ = a.Authenticate(t.Context(), username, "the-wrong-password", nil)
		return time.Since(start)
	}

	known := measure("svc-printer")
	unknown := measure("does-not-exist")

	// Timing on a loaded machine is noisy, so this only asserts the same order
	// of magnitude — enough to catch the "return immediately" regression.
	if unknown*4 < known {
		t.Errorf("an unknown username took %v against %v for a known one; the difference leaks which usernames exist",
			unknown, known)
	}
}

func TestAuthenticateUpgradesAWeakStoredHash(t *testing.T) {
	t.Parallel()

	a, db := newAuthenticator(t)
	account, _ := seedAccount(t, db, nil)

	// The fixture stores a deliberately cheap hash, so authenticating should
	// transparently upgrade it to the current parameters.
	before, err := db.Accounts().Get(t.Context(), account.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := a.Authenticate(t.Context(), account.Username, testPassword, nil); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	after, err := db.Accounts().Get(t.Context(), account.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.PasswordHash == before.PasswordHash {
		t.Error("a weakly hashed password was not upgraded on login")
	}
	// The upgraded hash must still verify the same password.
	match, _, err := appcrypto.VerifyPassword(after.PasswordHash, testPassword)
	if err != nil || !match {
		t.Errorf("the upgraded hash does not verify the password: match=%v err=%v", match, err)
	}
}

func TestAuthenticateRejectsAnUnusableStoredHash(t *testing.T) {
	t.Parallel()

	a, db := newAuthenticator(t)
	account, _ := seedAccount(t, db, func(acc *store.SMTPAccount) {
		acc.PasswordHash = "not-a-hash"
	})

	if _, err := a.Authenticate(t.Context(), account.Username, testPassword, nil); !errors.Is(err, smtpsrv.ErrAuthFailed) {
		t.Errorf("Authenticate = %v, want ErrAuthFailed", err)
	}
}
