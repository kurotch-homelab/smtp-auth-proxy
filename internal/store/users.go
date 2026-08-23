package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AdminUser is someone who can sign in to the management interface.
type AdminUser struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
	// PasswordHash is NULL for users that only sign in through the identity
	// provider.
	PasswordHash sql.NullString
	Role         Role
	// Source is local or oidc.
	Source string
	// Subject is the identity provider's stable claim for this user.
	Subject sql.NullString

	TOTPSecretEnc  string
	TOTPEnrolledAt sql.NullTime

	Disabled     bool
	FailedLogins int
	LockedUntil  sql.NullTime
	LastLoginAt  sql.NullTime

	CreatedAt time.Time
	UpdatedAt time.Time
}

// User sources.
const (
	// SourceLocal is a username and password held by the proxy.
	SourceLocal = "local"
	// SourceOIDC is an identity from the configured provider.
	SourceOIDC = "oidc"
)

// TOTPContext binds the sealed TOTP seed to this user's row.
func (u *AdminUser) TOTPContext() string { return "admin_users/totp_secret/" + u.ID }

// LockedAt reports whether the account is locked out at the given time.
func (u *AdminUser) LockedAt(now time.Time) bool {
	return u.LockedUntil.Valid && u.LockedUntil.Time.After(now)
}

// CanSignIn reports whether the account may authenticate at all.
func (u *AdminUser) CanSignIn(now time.Time) bool {
	return !u.Disabled && !u.LockedAt(now)
}

// UserRepo reads and writes admin users.
type UserRepo struct{ db *DB }

// Users returns the admin user repository.
func (db *DB) Users() *UserRepo { return &UserRepo{db: db} }

const userColumns = `
	id, username, email, display_name, password_hash, role, source, subject,
	totp_secret_enc, totp_enrolled_at, disabled, failed_logins, locked_until,
	last_login_at, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*AdminUser, error) {
	var u AdminUser
	err := row.Scan(
		&u.ID, &u.Username, &u.Email, &u.DisplayName, &u.PasswordHash, &u.Role,
		&u.Source, &u.Subject, &u.TOTPSecretEnc, &u.TOTPEnrolledAt, &u.Disabled,
		&u.FailedLogins, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// Create inserts a user.
func (r *UserRepo) Create(ctx context.Context, u *AdminUser) error {
	if u.ID == "" {
		u.ID = NewID()
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	if u.Source == "" {
		u.Source = SourceLocal
	}

	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO admin_users (`+userColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		u.ID, u.Username, u.Email, u.DisplayName, u.PasswordHash, u.Role,
		u.Source, u.Subject, u.TOTPSecretEnc, utcNull(u.TOTPEnrolledAt), u.Disabled,
		u.FailedLogins, utcNull(u.LockedUntil), utcNull(u.LastLoginAt), u.CreatedAt, u.UpdatedAt)
	return translateError(r.db.Dialect(), err, "user "+u.Username)
}

// Get returns one user by ID.
func (r *UserRepo) Get(ctx context.Context, id string) (*AdminUser, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+userColumns+` FROM admin_users WHERE id = ?`), id)
	u, err := scanUser(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "user "+id)
	}
	return u, nil
}

// GetByUsername returns one local user by name.
func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*AdminUser, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+userColumns+` FROM admin_users WHERE username = ?`), username)
	u, err := scanUser(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "user "+username)
	}
	return u, nil
}

// GetBySubject returns the user matching an identity provider's subject claim.
func (r *UserRepo) GetBySubject(ctx context.Context, source, subject string) (*AdminUser, error) {
	row := r.db.QueryRowContext(ctx, r.db.Rebind(
		`SELECT `+userColumns+` FROM admin_users WHERE source = ? AND subject = ?`), source, subject)
	u, err := scanUser(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "user with subject "+subject)
	}
	return u, nil
}

// List returns every user, ordered by username.
func (r *UserRepo) List(ctx context.Context) ([]*AdminUser, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+userColumns+` FROM admin_users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: listing users: %w", err)
	}
	defer rows.Close()

	var out []*AdminUser
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning user: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Update writes every mutable field except the login counters, which the
// authentication path owns.
func (r *UserRepo) Update(ctx context.Context, u *AdminUser) error {
	u.UpdatedAt = time.Now().UTC()

	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE admin_users SET
			username = ?, email = ?, display_name = ?, password_hash = ?, role = ?,
			source = ?, subject = ?, totp_secret_enc = ?, totp_enrolled_at = ?,
			disabled = ?, updated_at = ?
		WHERE id = ?`),
		u.Username, u.Email, u.DisplayName, u.PasswordHash, u.Role,
		u.Source, u.Subject, u.TOTPSecretEnc, utcNull(u.TOTPEnrolledAt),
		u.Disabled, u.UpdatedAt, u.ID)
	if err != nil {
		return translateError(r.db.Dialect(), err, "user "+u.Username)
	}
	return requireOneRow(res, "user "+u.ID)
}

// Delete removes a user and, by cascade, their sessions.
func (r *UserRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM admin_users WHERE id = ?`), id)
	if err != nil {
		return translateError(r.db.Dialect(), err, "user "+id)
	}
	return requireOneRow(res, "user "+id)
}

// CountByRole returns how many users hold each role.
//
// It exists so the API can refuse to remove the last administrator, which would
// otherwise lock everyone out of their own proxy.
func (r *UserRepo) CountByRole(ctx context.Context) (map[Role]int, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT role, COUNT(*) FROM admin_users WHERE disabled = FALSE GROUP BY role`)
	if err != nil {
		return nil, fmt.Errorf("store: counting users by role: %w", err)
	}
	defer rows.Close()

	out := map[Role]int{}
	for rows.Next() {
		var (
			role Role
			n    int
		)
		if err := rows.Scan(&role, &n); err != nil {
			return nil, fmt.Errorf("store: scanning role count: %w", err)
		}
		out[role] = n
	}
	return out, rows.Err()
}

// RecordFailedLogin increments the failure counter and locks the account once
// it reaches the threshold.
func (r *UserRepo) RecordFailedLogin(ctx context.Context, id string, threshold int, lockFor time.Duration) error {
	now := time.Now().UTC()

	return r.db.InTx(ctx, func(tx *Tx) error {
		var failures int
		err := tx.QueryRowContext(ctx,
			tx.Rebind(`SELECT failed_logins FROM admin_users WHERE id = ?`), id).Scan(&failures)
		if err != nil {
			return translateError(r.db.Dialect(), err, "user "+id)
		}
		failures++

		var lockedUntil sql.NullTime
		if threshold > 0 && failures >= threshold {
			lockedUntil = NullTime(now.Add(lockFor))
		}

		_, err = tx.ExecContext(ctx, tx.Rebind(
			`UPDATE admin_users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?`),
			failures, lockedUntil, now, id)
		return err
	})
}

// RecordSuccessfulLogin clears the failure counters and stamps the login time.
func (r *UserRepo) RecordSuccessfulLogin(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE admin_users SET
			failed_logins = 0, locked_until = NULL, last_login_at = ?, updated_at = ?
		WHERE id = ?`), now, now, id)
	return err
}
