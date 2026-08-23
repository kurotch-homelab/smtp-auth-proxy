package store

import (
	"context"
	"fmt"
	"time"
)

// MailboxRepo reads and writes the shared mailboxes the proxy sends as.
type MailboxRepo struct{ db *DB }

// Mailboxes returns the mailbox repository.
func (db *DB) Mailboxes() *MailboxRepo { return &MailboxRepo{db: db} }

const mailboxColumns = `
	id, address, display_name, oauth_credential_id, transport,
	rate_limit_per_min, max_concurrent, enabled, managed_by, created_at, updated_at`

func scanMailbox(row interface{ Scan(...any) error }) (*Mailbox, error) {
	var m Mailbox
	err := row.Scan(
		&m.ID, &m.Address, &m.DisplayName, &m.OAuthCredentialID, &m.Transport,
		&m.RateLimitPerMin, &m.MaxConcurrent, &m.Enabled, &m.ManagedBy,
		&m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Create inserts a mailbox, assigning its ID and timestamps.
func (r *MailboxRepo) Create(ctx context.Context, m *Mailbox) error {
	if m.ID == "" {
		m.ID = NewID()
	}
	now := time.Now().UTC()
	m.CreatedAt, m.UpdatedAt = now, now
	if m.ManagedBy == "" {
		m.ManagedBy = ManagedByUI
	}
	if m.Transport == "" {
		m.Transport = TransportSMTP
	}

	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO mailboxes (`+mailboxColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		m.ID, m.Address, m.DisplayName, m.OAuthCredentialID, m.Transport,
		m.RateLimitPerMin, m.MaxConcurrent, m.Enabled, m.ManagedBy,
		m.CreatedAt, m.UpdatedAt)
	return translateError(r.db.Dialect(), err, "mailbox "+m.Address)
}

// Get returns one mailbox by ID.
func (r *MailboxRepo) Get(ctx context.Context, id string) (*Mailbox, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+mailboxColumns+` FROM mailboxes WHERE id = ?`), id)
	m, err := scanMailbox(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "mailbox "+id)
	}
	return m, nil
}

// GetByAddress returns one mailbox by its unique address.
func (r *MailboxRepo) GetByAddress(ctx context.Context, address string) (*Mailbox, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+mailboxColumns+` FROM mailboxes WHERE address = ?`), address)
	m, err := scanMailbox(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "mailbox "+address)
	}
	return m, nil
}

// List returns every mailbox, ordered by address.
func (r *MailboxRepo) List(ctx context.Context) ([]*Mailbox, error) {
	return r.query(ctx, `SELECT `+mailboxColumns+` FROM mailboxes ORDER BY address`)
}

// ListForAccount returns the mailboxes an SMTP account may send as, ordered by
// address. The account's default mailbox is included even if the join table
// does not mention it, so a single-mailbox account needs only one setting.
func (r *MailboxRepo) ListForAccount(ctx context.Context, accountID string) ([]*Mailbox, error) {
	return r.query(ctx, r.db.Rebind(`
		SELECT `+prefixColumns("m", mailboxColumns)+`
		FROM mailboxes m
		WHERE m.id IN (
			SELECT mailbox_id FROM smtp_account_mailboxes WHERE smtp_account_id = ?
			UNION
			SELECT default_mailbox_id FROM smtp_accounts
			WHERE id = ? AND default_mailbox_id IS NOT NULL
		)
		ORDER BY m.address`), accountID, accountID)
}

func (r *MailboxRepo) query(ctx context.Context, query string, args ...any) ([]*Mailbox, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing mailboxes: %w", err)
	}
	defer rows.Close()

	var out []*Mailbox
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning mailbox: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Update writes every mutable field.
func (r *MailboxRepo) Update(ctx context.Context, m *Mailbox) error {
	m.UpdatedAt = time.Now().UTC()

	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE mailboxes SET
			address = ?, display_name = ?, oauth_credential_id = ?, transport = ?,
			rate_limit_per_min = ?, max_concurrent = ?, enabled = ?,
			managed_by = ?, updated_at = ?
		WHERE id = ?`),
		m.Address, m.DisplayName, m.OAuthCredentialID, m.Transport,
		m.RateLimitPerMin, m.MaxConcurrent, m.Enabled, m.ManagedBy, m.UpdatedAt, m.ID)
	if err != nil {
		return translateError(r.db.Dialect(), err, "mailbox "+m.Address)
	}
	return requireOneRow(res, "mailbox "+m.ID)
}

// Delete removes a mailbox. Accounts that referenced it keep working with their
// remaining mailboxes; queued messages keep their denormalized address so the
// history stays readable.
func (r *MailboxRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM mailboxes WHERE id = ?`), id)
	if err != nil {
		return translateError(r.db.Dialect(), err, "mailbox "+id)
	}
	return requireOneRow(res, "mailbox "+id)
}

// prefixColumns qualifies a column list with a table alias, so a join can reuse
// the same list without ambiguity.
func prefixColumns(alias, columns string) string {
	var out []byte
	for i, part := range splitColumns(columns) {
		if i > 0 {
			out = append(out, ", "...)
		}
		out = append(out, alias...)
		out = append(out, '.')
		out = append(out, part...)
	}
	return string(out)
}
