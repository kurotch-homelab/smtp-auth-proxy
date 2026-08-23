package store

import (
	"context"
	"fmt"
	"time"
)

// AccountRepo reads and writes the per-service SMTP credentials.
type AccountRepo struct{ db *DB }

// Accounts returns the SMTP account repository.
func (db *DB) Accounts() *AccountRepo { return &AccountRepo{db: db} }

const accountColumns = `
	id, username, password_hash, description, default_mailbox_id, from_policy,
	allow_cidrs, rate_limit_per_min, enabled, last_used_at, managed_by,
	created_at, updated_at`

func scanAccount(row interface{ Scan(...any) error }) (*SMTPAccount, error) {
	var (
		a     SMTPAccount
		cidrs string
	)
	err := row.Scan(
		&a.ID, &a.Username, &a.PasswordHash, &a.Description, &a.DefaultMailboxID,
		&a.FromPolicy, &cidrs, &a.RateLimitPerMin, &a.Enabled, &a.LastUsedAt,
		&a.ManagedBy, &a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if a.AllowCIDRs, err = unmarshalList(cidrs); err != nil {
		return nil, err
	}
	return &a, nil
}

// Create inserts an account, assigning its ID and timestamps.
func (r *AccountRepo) Create(ctx context.Context, a *SMTPAccount) error {
	if a.ID == "" {
		a.ID = NewID()
	}
	now := time.Now().UTC()
	a.CreatedAt, a.UpdatedAt = now, now
	if a.ManagedBy == "" {
		a.ManagedBy = ManagedByUI
	}
	if a.FromPolicy == "" {
		a.FromPolicy = FromPolicyReject
	}

	cidrs, err := marshalList(a.AllowCIDRs)
	if err != nil {
		return err
	}

	_, err = r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO smtp_accounts (`+accountColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.ID, a.Username, a.PasswordHash, a.Description, a.DefaultMailboxID,
		a.FromPolicy, cidrs, a.RateLimitPerMin, a.Enabled, utcNull(a.LastUsedAt),
		a.ManagedBy, a.CreatedAt, a.UpdatedAt)
	return translateError(r.db.Dialect(), err, "SMTP account "+a.Username)
}

// Get returns one account by ID.
func (r *AccountRepo) Get(ctx context.Context, id string) (*SMTPAccount, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+accountColumns+` FROM smtp_accounts WHERE id = ?`), id)
	a, err := scanAccount(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "SMTP account "+id)
	}
	return a, nil
}

// GetByUsername returns one account by the username a client authenticates with.
//
// It returns ErrNotFound for a username that does not exist. Callers on the
// authentication path must not let that distinction reach the client: an SMTP
// server that answers differently for an unknown user than for a wrong password
// hands an attacker a list of valid usernames.
func (r *AccountRepo) GetByUsername(ctx context.Context, username string) (*SMTPAccount, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+accountColumns+` FROM smtp_accounts WHERE username = ?`), username)
	a, err := scanAccount(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "SMTP account "+username)
	}
	return a, nil
}

// List returns every account, ordered by username.
func (r *AccountRepo) List(ctx context.Context) ([]*SMTPAccount, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+accountColumns+` FROM smtp_accounts ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: listing SMTP accounts: %w", err)
	}
	defer rows.Close()

	var out []*SMTPAccount
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning SMTP account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Update writes every mutable field except last_used_at, which the SMTP path
// updates on its own so a busy account does not fight the admin UI.
func (r *AccountRepo) Update(ctx context.Context, a *SMTPAccount) error {
	a.UpdatedAt = time.Now().UTC()

	cidrs, err := marshalList(a.AllowCIDRs)
	if err != nil {
		return err
	}

	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE smtp_accounts SET
			username = ?, password_hash = ?, description = ?, default_mailbox_id = ?,
			from_policy = ?, allow_cidrs = ?, rate_limit_per_min = ?, enabled = ?,
			managed_by = ?, updated_at = ?
		WHERE id = ?`),
		a.Username, a.PasswordHash, a.Description, a.DefaultMailboxID,
		a.FromPolicy, cidrs, a.RateLimitPerMin, a.Enabled,
		a.ManagedBy, a.UpdatedAt, a.ID)
	if err != nil {
		return translateError(r.db.Dialect(), err, "SMTP account "+a.Username)
	}
	return requireOneRow(res, "SMTP account "+a.ID)
}

// TouchLastUsed records a successful authentication.
//
// It is deliberately best-effort and separate from Update: this runs on every
// submission, and a write failure here must never fail the delivery.
func (r *AccountRepo) TouchLastUsed(ctx context.Context, id string, at time.Time) error {
	_, err := r.db.ExecContext(ctx,
		r.db.Rebind(`UPDATE smtp_accounts SET last_used_at = ? WHERE id = ?`), at.UTC(), id)
	return err
}

// Delete removes an account and, by cascade, its mailbox links and allowed
// senders. Messages it submitted are retained with their username preserved.
func (r *AccountRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM smtp_accounts WHERE id = ?`), id)
	if err != nil {
		return translateError(r.db.Dialect(), err, "SMTP account "+id)
	}
	return requireOneRow(res, "SMTP account "+id)
}

// SetMailboxes replaces the set of mailboxes an account may send as.
func (r *AccountRepo) SetMailboxes(ctx context.Context, accountID string, mailboxIDs []string) error {
	return r.db.InTx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx,
			tx.Rebind(`DELETE FROM smtp_account_mailboxes WHERE smtp_account_id = ?`), accountID); err != nil {
			return fmt.Errorf("store: clearing mailbox links: %w", err)
		}

		seen := make(map[string]struct{}, len(mailboxIDs))
		for _, id := range mailboxIDs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}

			_, err := tx.ExecContext(ctx, tx.Rebind(
				`INSERT INTO smtp_account_mailboxes (smtp_account_id, mailbox_id) VALUES (?, ?)`),
				accountID, id)
			if err != nil {
				return translateError(r.db.Dialect(), err, "mailbox link "+id)
			}
		}
		return nil
	})
}

// AllowedSenders returns the extra From patterns an account may use.
func (r *AccountRepo) AllowedSenders(ctx context.Context, accountID string) ([]*AllowedSender, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(
		`SELECT id, smtp_account_id, pattern, created_at
		 FROM allowed_senders WHERE smtp_account_id = ? ORDER BY pattern`), accountID)
	if err != nil {
		return nil, fmt.Errorf("store: listing allowed senders: %w", err)
	}
	defer rows.Close()

	var out []*AllowedSender
	for rows.Next() {
		var s AllowedSender
		if err := rows.Scan(&s.ID, &s.SMTPAccountID, &s.Pattern, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning allowed sender: %w", err)
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// SetAllowedSenders replaces an account's extra From patterns.
func (r *AccountRepo) SetAllowedSenders(ctx context.Context, accountID string, patterns []string) error {
	now := time.Now().UTC()

	return r.db.InTx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx,
			tx.Rebind(`DELETE FROM allowed_senders WHERE smtp_account_id = ?`), accountID); err != nil {
			return fmt.Errorf("store: clearing allowed senders: %w", err)
		}

		seen := make(map[string]struct{}, len(patterns))
		for _, p := range patterns {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}

			_, err := tx.ExecContext(ctx, tx.Rebind(
				`INSERT INTO allowed_senders (id, smtp_account_id, pattern, created_at)
				 VALUES (?, ?, ?, ?)`), NewID(), accountID, p, now)
			if err != nil {
				return translateError(r.db.Dialect(), err, "allowed sender "+p)
			}
		}
		return nil
	})
}
