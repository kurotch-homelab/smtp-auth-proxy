package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// authenticator verifies SMTP credentials against the database.
type authenticator struct {
	db  *store.DB
	log *slog.Logger
}

// decoyHash is verified when the username does not exist.
//
// Without it, an unknown username returns immediately while a known one waits
// for Argon2, and the difference is easily measurable — which turns the SMTP
// port into a way to enumerate every service account on the network.
var decoyHash = mustHash("a password nobody has")

func mustHash(s string) string {
	h, err := appcrypto.HashPassword(s)
	if err != nil {
		panic(fmt.Sprintf("app: hashing the decoy password: %v", err))
	}
	return h
}

// Authenticate implements smtpsrv.Authenticator.
func (a *authenticator) Authenticate(ctx context.Context, username, password string, remote net.IP) (*smtpsrv.Identity, error) {
	account, err := a.db.Accounts().GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Spend the same time as a real verification would.
			_, _, _ = appcrypto.VerifyPassword(decoyHash, password)
			return nil, fmt.Errorf("%w: no account named %q", smtpsrv.ErrAuthFailed, username)
		}
		return nil, fmt.Errorf("%w: looking up %q: %w", smtpsrv.ErrAuthFailed, username, err)
	}

	match, needsRehash, verifyErr := appcrypto.VerifyPassword(account.PasswordHash, password)
	if verifyErr != nil {
		return nil, fmt.Errorf("%w: the stored password hash for %q is unusable: %w",
			smtpsrv.ErrAuthFailed, username, verifyErr)
	}
	if !match {
		return nil, fmt.Errorf("%w: wrong password for %q", smtpsrv.ErrAuthFailed, username)
	}

	// Everything below is checked after the password, so a wrong password and a
	// disabled account cost the same and reveal the same.
	if !account.Enabled {
		return nil, fmt.Errorf("%w: account %q is disabled", smtpsrv.ErrAuthFailed, username)
	}

	allowed, err := a.db.Accounts().AllowedSenders(ctx, account.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: loading allowed senders for %q: %w", smtpsrv.ErrAuthFailed, username, err)
	}
	policyAccount := policy.AccountFromStore(account, allowed)

	if sourceErr := policy.CheckSourceAddress(policyAccount, remote); sourceErr != nil {
		return nil, fmt.Errorf("%w: %w", smtpsrv.ErrAuthFailed, sourceErr)
	}

	mailboxes, err := a.db.Mailboxes().ListForAccount(ctx, account.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: loading mailboxes for %q: %w", smtpsrv.ErrAuthFailed, username, err)
	}

	if needsRehash {
		a.rehash(ctx, account, password)
	}
	// Recording last use must never fail an otherwise valid submission.
	if err := a.db.Accounts().TouchLastUsed(ctx, account.ID, time.Now().UTC()); err != nil {
		a.log.Warn("could not record last use of an SMTP account",
			"username", username, "reason", err)
	}

	return &smtpsrv.Identity{
		AccountID: account.ID,
		Username:  account.Username,
		Account:   policyAccount,
		Mailboxes: mailboxes,
	}, nil
}

// rehash upgrades a password stored with weaker parameters than the current
// defaults, so raising the cost takes effect without asking operators to
// reissue every device password.
func (a *authenticator) rehash(ctx context.Context, account *store.SMTPAccount, password string) {
	updated, err := appcrypto.HashPassword(password)
	if err != nil {
		a.log.Warn("could not rehash a password", "username", account.Username, "reason", err)
		return
	}

	account.PasswordHash = updated
	if err := a.db.Accounts().Update(ctx, account); err != nil {
		a.log.Warn("could not store a rehashed password", "username", account.Username, "reason", err)
		return
	}
	a.log.Info("upgraded a stored password to the current hashing parameters", "username", account.Username)
}
