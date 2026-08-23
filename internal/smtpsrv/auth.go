package smtpsrv

import (
	"context"
	"errors"
	"net"

	"github.com/emersion/go-sasl"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// ErrAuthFailed is returned for every authentication failure.
//
// There is deliberately one error for "no such account", "wrong password",
// "disabled" and "not allowed from this address". An SMTP server that
// distinguishes them hands an attacker a way to enumerate valid usernames, and
// the operator can see the real reason in the logs.
var ErrAuthFailed = errors.New("smtpsrv: authentication failed")

// Identity is a successfully authenticated account together with everything the
// session needs to evaluate a submission.
type Identity struct {
	AccountID string
	Username  string
	Account   policy.Account
	Mailboxes []*store.Mailbox
}

// Authenticator verifies SMTP credentials.
type Authenticator interface {
	// Authenticate returns the identity behind a username and password, or
	// ErrAuthFailed. It must not distinguish failure reasons to the caller.
	Authenticate(ctx context.Context, username, password string, remote net.IP) (*Identity, error)
}

// saslServers builds the SASL mechanisms offered on a connection.
//
// Only PLAIN and LOGIN are offered: they are what devices implement, and both
// send the password in the clear, which is why the server refuses to advertise
// AUTH at all until the connection is encrypted (unless the operator has
// explicitly opted out).
func (s *session) saslServers(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			// The authorization identity is the "act as" field. Nothing here
			// supports acting as another account, so it must be empty or equal.
			if identity != "" && identity != username {
				s.recordAuthFailure(username, errors.New("SASL authorization identity is not supported"))
				return ErrAuthFailed
			}
			return s.authenticate(username, password)
		}), nil

	case sasl.Login:
		return newLoginServer(func(username, password string) error {
			return s.authenticate(username, password)
		}), nil

	default:
		return nil, ErrAuthFailed
	}
}
