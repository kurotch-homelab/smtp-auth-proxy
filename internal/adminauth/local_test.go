package adminauth_test

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

const adminPassword = "correct horse battery staple"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// cheapParams keep the tests fast.
func cheapParams() appcrypto.Argon2Params {
	return appcrypto.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func seedAdmin(t *testing.T, db *store.DB, username string, mutate func(*store.AdminUser)) *store.AdminUser {
	t.Helper()

	hash, err := appcrypto.HashPasswordWith(adminPassword, cheapParams())
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	u := &store.AdminUser{
		Username:     username,
		Email:        username + "@example.com",
		PasswordHash: store.NullString(hash),
		Role:         store.RoleAdmin,
		Source:       store.SourceLocal,
	}
	if mutate != nil {
		mutate(u)
	}
	if err := db.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("creating %q: %v", username, err)
	}
	return u
}

func localAuth(t *testing.T, cfg adminauth.LocalConfig) (*adminauth.LocalAuthenticator, *store.DB) {
	t.Helper()

	db := storetest.Open(t, store.DriverSQLite)
	return adminauth.NewLocalAuthenticator(db, cfg, discardLogger()), db
}

func TestLocalAuthenticate(t *testing.T) {
	t.Parallel()

	a, db := localAuth(t, adminauth.LocalConfig{Enabled: true, LockoutThreshold: 3, LockoutDuration: time.Minute})
	seedAdmin(t, db, "alice", nil)

	user, err := a.Authenticate(t.Context(), "alice", adminPassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if user.Username != "alice" || user.Role != store.RoleAdmin {
		t.Errorf("Authenticate returned %+v", user)
	}
}

func TestLocalAuthenticateRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*store.AdminUser)
		username string
		password string
		want     error
	}{
		{name: "unknown username", username: "nobody", password: adminPassword, want: adminauth.ErrInvalidCredentials},
		{name: "wrong password", username: "alice", password: "wrong", want: adminauth.ErrInvalidCredentials},
		{
			name:     "disabled account",
			mutate:   func(u *store.AdminUser) { u.Disabled = true },
			username: "alice", password: adminPassword,
			want: adminauth.ErrInvalidCredentials,
		},
		{
			// An account provisioned through single sign-on has no password to
			// check, and must not be signable-into with an empty one.
			name:     "single sign-on account has no password",
			mutate:   func(u *store.AdminUser) { u.PasswordHash = store.NullString(""); u.Source = store.SourceOIDC },
			username: "alice", password: "",
			want: adminauth.ErrInvalidCredentials,
		},
		{
			name:     "unusable stored hash",
			mutate:   func(u *store.AdminUser) { u.PasswordHash = store.NullString("not-a-hash") },
			username: "alice", password: adminPassword,
			want: adminauth.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, db := localAuth(t, adminauth.LocalConfig{Enabled: true})
			seedAdmin(t, db, "alice", tt.mutate)

			_, err := a.Authenticate(t.Context(), tt.username, tt.password)
			if !errors.Is(err, tt.want) {
				t.Errorf("Authenticate = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestLocalAuthenticateDisabled(t *testing.T) {
	t.Parallel()

	a, db := localAuth(t, adminauth.LocalConfig{Enabled: false})
	seedAdmin(t, db, "alice", nil)

	if _, err := a.Authenticate(t.Context(), "alice", adminPassword); !errors.Is(err, adminauth.ErrLocalDisabled) {
		t.Errorf("Authenticate = %v, want ErrLocalDisabled", err)
	}
}

func TestLocalLockout(t *testing.T) {
	t.Parallel()

	a, db := localAuth(t, adminauth.LocalConfig{Enabled: true, LockoutThreshold: 3, LockoutDuration: time.Hour})
	seedAdmin(t, db, "alice", nil)

	for i := range 3 {
		if _, err := a.Authenticate(t.Context(), "alice", "wrong"); !errors.Is(err, adminauth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", i, err)
		}
	}

	// The right password must now be refused too, or the lockout is decorative.
	if _, err := a.Authenticate(t.Context(), "alice", adminPassword); !errors.Is(err, adminauth.ErrLockedOut) {
		t.Errorf("Authenticate after the lockout = %v, want ErrLockedOut", err)
	}
}

func TestLocalSuccessfulSignInClearsTheCounter(t *testing.T) {
	t.Parallel()

	a, db := localAuth(t, adminauth.LocalConfig{Enabled: true, LockoutThreshold: 3, LockoutDuration: time.Hour})
	u := seedAdmin(t, db, "alice", nil)

	for range 2 {
		_, _ = a.Authenticate(t.Context(), "alice", "wrong")
	}
	if _, err := a.Authenticate(t.Context(), "alice", adminPassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	got, err := db.Users().Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Otherwise two typos a week apart would eventually lock a working account.
	if got.FailedLogins != 0 {
		t.Errorf("FailedLogins = %d after a successful sign-in, want 0", got.FailedLogins)
	}
	if !got.LastLoginAt.Valid {
		t.Error("LastLoginAt was not stamped")
	}
}

// An unknown username must cost roughly what a known one does, or the sign-in
// page becomes a way to enumerate who administers this proxy.
func TestUnknownUsernameCostsTheSameEffort(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a := adminauth.NewLocalAuthenticator(db, adminauth.LocalConfig{Enabled: true}, discardLogger())

	// Real hashing parameters, so the comparison means something.
	hash, err := appcrypto.HashPassword(adminPassword)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	seedAdmin(t, db, "alice", func(u *store.AdminUser) { u.PasswordHash = store.NullString(hash) })

	measure := func(username string) time.Duration {
		start := time.Now()
		_, _ = a.Authenticate(t.Context(), username, "the-wrong-password")
		return time.Since(start)
	}

	known := measure("alice")
	unknown := measure("does-not-exist")

	if unknown*4 < known {
		t.Errorf("an unknown username took %v against %v for a known one; the difference leaks who exists",
			unknown, known)
	}
}

func TestLocalRehashesAWeakStoredPassword(t *testing.T) {
	t.Parallel()

	a, db := localAuth(t, adminauth.LocalConfig{Enabled: true})
	u := seedAdmin(t, db, "alice", nil)

	before, err := db.Users().Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := a.Authenticate(t.Context(), "alice", adminPassword); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	after, err := db.Users().Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.PasswordHash.String == before.PasswordHash.String {
		t.Error("a weakly hashed password was not upgraded on sign-in")
	}
	if _, err := a.Authenticate(t.Context(), "alice", adminPassword); err != nil {
		t.Errorf("the upgraded hash no longer verifies: %v", err)
	}
}

// A password is usually changed because the old one may be known to someone
// else, so leaving existing sessions alive would make the change pointless.
func TestSetPasswordEndsExistingSessions(t *testing.T) {
	t.Parallel()

	a, db := localAuth(t, adminauth.LocalConfig{Enabled: true})
	u := seedAdmin(t, db, "alice", nil)

	s := &store.Session{
		UserID:    u.ID,
		TokenHash: store.HashSessionToken("the-token"),
		CSRFToken: "csrf",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := db.Sessions().Create(t.Context(), s); err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	if err := a.SetPassword(t.Context(), u, "a-brand-new-password"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, err := db.Sessions().Lookup(t.Context(), "the-token", time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a session survived a password change: %v", err)
	}
	if _, err := a.Authenticate(t.Context(), "alice", "a-brand-new-password"); err != nil {
		t.Errorf("the new password does not work: %v", err)
	}
	if _, err := a.Authenticate(t.Context(), "alice", adminPassword); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Error("the old password still works")
	}
}
