package adminauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Sign-in errors.
//
// ErrInvalidCredentials covers an unknown username, a wrong password and a
// disabled account alike: telling them apart would let anyone with the sign-in
// page enumerate who administers this proxy.
var (
	ErrInvalidCredentials = errors.New("adminauth: incorrect username or password")
	// ErrLockedOut is separate because the user needs to know to wait rather
	// than keep guessing — and reaching it already required the right username.
	ErrLockedOut = errors.New("adminauth: too many failed attempts; try again later")
	// ErrLocalDisabled means password sign-in is switched off entirely.
	ErrLocalDisabled = errors.New("adminauth: password sign-in is disabled")
)

// LocalConfig configures password sign-in.
type LocalConfig struct {
	Enabled bool
	// LockoutThreshold is how many consecutive failures lock an account. Zero
	// disables lockout.
	LockoutThreshold int
	// LockoutDuration is how long the lock lasts.
	LockoutDuration time.Duration
}

// decoyHash is verified when the username does not exist, so an unknown user
// costs the same as a known one. Without it the sign-in page answers
// immediately for names that do not exist, which is enough to enumerate them.
var decoyHash = mustHash("a password nobody has")

func mustHash(s string) string {
	h, err := appcrypto.HashPassword(s)
	if err != nil {
		panic(fmt.Sprintf("adminauth: hashing the decoy password: %v", err))
	}
	return h
}

// LocalAuthenticator verifies usernames and passwords.
type LocalAuthenticator struct {
	db  *store.DB
	cfg LocalConfig
	log *slog.Logger
}

// NewLocalAuthenticator returns an authenticator.
func NewLocalAuthenticator(db *store.DB, cfg LocalConfig, log *slog.Logger) *LocalAuthenticator {
	if log == nil {
		log = slog.Default()
	}
	return &LocalAuthenticator{db: db, cfg: cfg, log: log}
}

// Authenticate verifies a username and password and returns the user.
func (a *LocalAuthenticator) Authenticate(ctx context.Context, username, password string) (*store.AdminUser, error) {
	if !a.cfg.Enabled {
		return nil, ErrLocalDisabled
	}

	user, err := a.db.Users().GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_, _, _ = appcrypto.VerifyPassword(decoyHash, password)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	now := time.Now().UTC()
	if user.LockedAt(now) {
		return nil, ErrLockedOut
	}
	if !user.PasswordHash.Valid || user.PasswordHash.String == "" {
		// An account provisioned through single sign-on has no password. Spend
		// the same effort as a real check anyway.
		_, _, _ = appcrypto.VerifyPassword(decoyHash, password)
		return nil, ErrInvalidCredentials
	}

	match, needsRehash, err := appcrypto.VerifyPassword(user.PasswordHash.String, password)
	if err != nil {
		a.log.Warn("a stored admin password hash is unusable",
			"username", username, "reason", err)
		return nil, ErrInvalidCredentials
	}
	if !match {
		a.recordFailure(ctx, user)
		return nil, ErrInvalidCredentials
	}

	// Checked after the password, so a disabled account and a wrong password
	// are indistinguishable from outside.
	if user.Disabled {
		return nil, ErrInvalidCredentials
	}

	if needsRehash {
		a.rehash(ctx, user, password)
	}
	if err := a.db.Users().RecordSuccessfulLogin(ctx, user.ID); err != nil {
		a.log.Warn("could not record a successful sign-in", "username", username, "reason", err)
	}
	return user, nil
}

func (a *LocalAuthenticator) recordFailure(ctx context.Context, user *store.AdminUser) {
	err := a.db.Users().RecordFailedLogin(ctx, user.ID, a.cfg.LockoutThreshold, a.cfg.LockoutDuration)
	if err != nil {
		a.log.Warn("could not record a failed sign-in", "username", user.Username, "reason", err)
	}
}

// rehash upgrades a password stored with weaker parameters than the current
// defaults, so raising the cost does not mean asking everyone to reset.
func (a *LocalAuthenticator) rehash(ctx context.Context, user *store.AdminUser, password string) {
	updated, err := appcrypto.HashPassword(password)
	if err != nil {
		a.log.Warn("could not rehash an admin password", "username", user.Username, "reason", err)
		return
	}

	user.PasswordHash = store.NullString(updated)
	if err := a.db.Users().Update(ctx, user); err != nil {
		a.log.Warn("could not store a rehashed admin password", "username", user.Username, "reason", err)
		return
	}
	a.log.Info("upgraded a stored admin password to the current hashing parameters",
		"username", user.Username)
}

// SetPassword changes a user's password and ends their other sessions.
//
// Ending them is the point: a password is usually changed because the old one
// may be known to someone else, and leaving their sessions alive would make the
// change pointless.
func (a *LocalAuthenticator) SetPassword(ctx context.Context, user *store.AdminUser, password string) error {
	hash, err := appcrypto.HashPassword(password)
	if err != nil {
		return fmt.Errorf("adminauth: hashing the password: %w", err)
	}

	user.PasswordHash = store.NullString(hash)
	if err := a.db.Users().Update(ctx, user); err != nil {
		return err
	}
	if _, err := a.db.Sessions().DeleteForUser(ctx, user.ID); err != nil {
		return fmt.Errorf("adminauth: revoking sessions after a password change: %w", err)
	}
	return nil
}
