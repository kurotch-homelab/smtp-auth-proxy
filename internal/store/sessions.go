package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Session is a signed-in admin session.
//
// The token itself is never stored: only its hash is, so a stolen database does
// not hand an attacker working sessions.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	CSRFToken string

	IP        string
	UserAgent string

	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// HashSessionToken derives the value stored for a session token.
//
// SHA-256 rather than a password hash: the token is 256 bits of entropy from a
// cryptographic source, so there is nothing to brute force, and this runs on
// every authenticated request.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SessionRepo reads and writes admin sessions.
type SessionRepo struct{ db *DB }

// Sessions returns the session repository.
func (db *DB) Sessions() *SessionRepo { return &SessionRepo{db: db} }

const sessionColumns = `
	id, user_id, token_hash, csrf_token, ip, user_agent,
	created_at, last_seen_at, expires_at`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CSRFToken, &s.IP, &s.UserAgent,
		&s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Create stores a session.
func (r *SessionRepo) Create(ctx context.Context, s *Session) error {
	if s.ID == "" {
		s.ID = NewID()
	}
	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.LastSeenAt = now
	// Every timestamp is normalized to UTC before it is written. SQLite stores
	// a time.Time as text including its offset, so a value in local time
	// compares wrong against one in UTC — an expired session would look live.
	s.CreatedAt = s.CreatedAt.UTC()
	s.ExpiresAt = s.ExpiresAt.UTC()

	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO admin_sessions (`+sessionColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		s.ID, s.UserID, s.TokenHash, s.CSRFToken, s.IP, s.UserAgent,
		s.CreatedAt, s.LastSeenAt, s.ExpiresAt)
	return translateError(r.db.Dialect(), err, "session")
}

// Authenticated is a session together with the user it belongs to.
type Authenticated struct {
	Session *Session
	User    *AdminUser
}

// Lookup returns the live session for a token, along with its user.
//
// Expiry and the idle timeout are enforced here rather than by the caller, so
// there is one place where a session stops being valid.
func (r *SessionRepo) Lookup(ctx context.Context, token string, idleTimeout time.Duration) (*Authenticated, error) {
	now := time.Now().UTC()

	row := r.db.QueryRowContext(ctx, r.db.Rebind(
		`SELECT `+prefixColumns("s", sessionColumns)+`, `+prefixColumns("u", userColumns)+`
		 FROM admin_sessions s
		 JOIN admin_users u ON u.id = s.user_id
		 WHERE s.token_hash = ?`), HashSessionToken(token))

	var (
		s Session
		u AdminUser
	)
	err := row.Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.CSRFToken, &s.IP, &s.UserAgent,
		&s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt,
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role,
		&u.Source, &u.Subject, &u.TOTPSecretEnc, &u.TOTPEnrolledAt, &u.Disabled,
		&u.FailedLogins, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "session")
	}

	if !s.ExpiresAt.After(now) {
		// Clean up as we go, so an abandoned browser does not leave rows behind
		// until the next sweep.
		_ = r.Delete(ctx, s.ID)
		return nil, fmt.Errorf("%w: the session has expired", ErrNotFound)
	}
	if idleTimeout > 0 && now.Sub(s.LastSeenAt) > idleTimeout {
		_ = r.Delete(ctx, s.ID)
		return nil, fmt.Errorf("%w: the session was idle too long", ErrNotFound)
	}
	if u.Disabled {
		return nil, fmt.Errorf("%w: the account is disabled", ErrNotFound)
	}

	return &Authenticated{Session: &s, User: &u}, nil
}

// Touch records activity, so the idle timeout measures inactivity rather than
// age.
func (r *SessionRepo) Touch(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		r.db.Rebind(`UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?`),
		time.Now().UTC(), id)
	return err
}

// Delete removes one session, which is what signing out does.
func (r *SessionRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM admin_sessions WHERE id = ?`), id)
	return err
}

// DeleteForUser removes every session a user holds.
//
// This runs when a password changes, a role changes or an account is disabled:
// leaving old sessions alive would mean a demoted user keeps their old
// privileges until they happen to sign out.
func (r *SessionRepo) DeleteForUser(ctx context.Context, userID string) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		r.db.Rebind(`DELETE FROM admin_sessions WHERE user_id = ?`), userID)
	if err != nil {
		return 0, fmt.Errorf("store: deleting sessions for %s: %w", userID, err)
	}
	return res.RowsAffected()
}

// ListForUser returns a user's live sessions, newest first, so they can see
// where they are signed in.
func (r *SessionRepo) ListForUser(ctx context.Context, userID string) ([]*Session, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(
		`SELECT `+sessionColumns+` FROM admin_sessions
		 WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC`),
		userID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("store: listing sessions: %w", err)
	}
	defer rows.Close()

	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning session: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PurgeExpired removes sessions that are past their lifetime.
func (r *SessionRepo) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx,
		r.db.Rebind(`DELETE FROM admin_sessions WHERE expires_at < ?`), time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("store: purging expired sessions: %w", err)
	}
	return res.RowsAffected()
}
