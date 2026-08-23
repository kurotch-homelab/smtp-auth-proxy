package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MessageRepo is the delivery queue and the sent-mail history.
type MessageRepo struct{ db *DB }

// Messages returns the message repository.
func (db *DB) Messages() *MessageRepo { return &MessageRepo{db: db} }

const messageColumns = `
	id, smtp_account_id, mailbox_id, account_username, mailbox_address,
	envelope_from, header_from, recipients, recipient_count, size_bytes,
	subject, message_id, status, attempts, next_attempt_at,
	lease_owner, lease_expires_at, last_error, last_error_code,
	last_error_permanent, client_ip, blob_ref, received_at, sent_at, updated_at`

func scanMessage(row interface{ Scan(...any) error }) (*Message, error) {
	var (
		m          Message
		recipients string
	)
	err := row.Scan(
		&m.ID, &m.SMTPAccountID, &m.MailboxID, &m.AccountUsername, &m.MailboxAddress,
		&m.EnvelopeFrom, &m.HeaderFrom, &recipients, &m.RecipientCount, &m.SizeBytes,
		&m.Subject, &m.MessageID, &m.Status, &m.Attempts, &m.NextAttemptAt,
		&m.LeaseOwner, &m.LeaseExpiresAt, &m.LastError, &m.LastErrorCode,
		&m.LastErrorPermanent, &m.ClientIP, &m.BlobRef, &m.ReceivedAt, &m.SentAt, &m.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if m.Recipients, err = unmarshalList(recipients); err != nil {
		return nil, err
	}
	return &m, nil
}

// Enqueue stores an accepted submission together with its MIME body, in one
// transaction: a message row with no body would be delivered as an empty
// message, and a body with no row would leak.
//
// body may be nil when storage.blob is fs, in which case the caller has already
// written the file and set BlobRef.
func (r *MessageRepo) Enqueue(ctx context.Context, m *Message, body []byte) error {
	if m.ID == "" {
		m.ID = NewID()
	}
	now := time.Now().UTC()
	if m.ReceivedAt.IsZero() {
		m.ReceivedAt = now
	}
	if m.NextAttemptAt.IsZero() {
		m.NextAttemptAt = now
	}
	m.ReceivedAt = utc(m.ReceivedAt)
	m.NextAttemptAt = utc(m.NextAttemptAt)
	m.SentAt = utcNull(m.SentAt)
	m.LeaseExpiresAt = utcNull(m.LeaseExpiresAt)
	m.UpdatedAt = now
	if m.Status == "" {
		m.Status = StatusQueued
	}
	m.RecipientCount = len(m.Recipients)

	recipients, err := marshalList(m.Recipients)
	if err != nil {
		return err
	}

	return r.db.InTx(ctx, func(tx *Tx) error {
		_, err := tx.ExecContext(ctx, tx.Rebind(`
			INSERT INTO messages (`+messageColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			m.ID, m.SMTPAccountID, m.MailboxID, m.AccountUsername, m.MailboxAddress,
			m.EnvelopeFrom, m.HeaderFrom, recipients, m.RecipientCount, m.SizeBytes,
			m.Subject, m.MessageID, m.Status, m.Attempts, m.NextAttemptAt,
			m.LeaseOwner, m.LeaseExpiresAt, m.LastError, m.LastErrorCode,
			m.LastErrorPermanent, m.ClientIP, m.BlobRef, m.ReceivedAt, m.SentAt, m.UpdatedAt)
		if err != nil {
			return translateError(r.db.Dialect(), err, "message "+m.ID)
		}

		if body == nil {
			return nil
		}
		if _, err := tx.ExecContext(ctx,
			tx.Rebind(`INSERT INTO message_blobs (message_id, content) VALUES (?, ?)`), m.ID, body); err != nil {
			return fmt.Errorf("store: storing the message body: %w", err)
		}
		return nil
	})
}

// Body returns a message's MIME content from the database.
func (r *MessageRepo) Body(ctx context.Context, id string) ([]byte, error) {
	var body []byte
	err := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT content FROM message_blobs WHERE message_id = ?`), id).Scan(&body)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "body of message "+id)
	}
	return body, nil
}

// Get returns one message.
func (r *MessageRepo) Get(ctx context.Context, id string) (*Message, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+messageColumns+` FROM messages WHERE id = ?`), id)
	m, err := scanMessage(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "message "+id)
	}
	return m, nil
}

// ClaimMessages leases up to limit due messages for one worker and returns them.
//
// The claim is a single atomic UPDATE rather than a select-then-update inside a
// transaction. On PostgreSQL the subquery takes FOR UPDATE SKIP LOCKED so
// replicas step around each other; on SQLite the statement is the whole write,
// which the engine already serializes. Either way two workers cannot end up
// holding the same message, and there is no read-to-write promotion that could
// fail halfway.
//
// A message is due when it is queued or deferred, its next attempt time has
// passed, and no live lease exists — which is also how a lease left behind by a
// crashed worker is reclaimed.
func (r *MessageRepo) ClaimMessages(ctx context.Context, owner string, limit int, leaseFor time.Duration) ([]*Message, error) {
	if owner == "" {
		return nil, errors.New("store: claiming requires a worker identity")
	}
	if limit <= 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	leaseUntil := now.Add(leaseFor)

	query := r.db.Rebind(`
		UPDATE messages SET
			status = 'sending', lease_owner = ?, lease_expires_at = ?, updated_at = ?
		WHERE id IN (
			SELECT id FROM messages
			WHERE (
				-- Due for its first or next attempt.
				(status IN ('queued', 'deferred') AND next_attempt_at <= ?)
				-- Or abandoned: a worker claimed it and never came back. It is
				-- retried immediately rather than waiting for next_attempt_at,
				-- which was already in the past when it was claimed.
				OR (status = 'sending' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?)
			)
			AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at < ?)
			ORDER BY next_attempt_at
			LIMIT ?` + r.db.Dialect().LockClause() + `
		)`)

	res, err := r.db.ExecContext(ctx, query, owner, leaseUntil, now, now, now, now, limit)
	if err != nil {
		return nil, fmt.Errorf("store: claiming messages: %w", err)
	}
	// Skip the read-back when nothing was claimed. RowsAffected is advisory
	// here: if the driver cannot report it, fall through and let the query
	// return an empty result.
	if n, rowsErr := res.RowsAffected(); rowsErr == nil && n == 0 {
		return nil, nil
	}

	// Read back exactly what this worker now owns.
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(
		`SELECT `+messageColumns+` FROM messages
		 WHERE lease_owner = ? AND lease_expires_at = ? AND status = 'sending'
		 ORDER BY next_attempt_at`), owner, leaseUntil)
	if err != nil {
		return nil, fmt.Errorf("store: reading claimed messages: %w", err)
	}
	defer rows.Close()

	var out []*Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning claimed message: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ExtendLease pushes a lease further out for a delivery that is still running,
// so a slow upstream does not let another worker take the message.
func (r *MessageRepo) ExtendLease(ctx context.Context, id, owner string, leaseFor time.Duration) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET lease_expires_at = ?, updated_at = ?
		WHERE id = ? AND lease_owner = ?`),
		time.Now().UTC().Add(leaseFor), time.Now().UTC(), id, owner)
	if err != nil {
		return fmt.Errorf("store: extending the lease on %s: %w", id, err)
	}
	return requireOneRow(res, "lease on message "+id)
}

// MarkSent records a successful delivery and releases the lease.
func (r *MessageRepo) MarkSent(ctx context.Context, id, owner string) error {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET
			status = 'sent', sent_at = ?, updated_at = ?,
			attempts = attempts + 1, lease_owner = NULL, lease_expires_at = NULL,
			last_error = '', last_error_code = ''
		WHERE id = ? AND lease_owner = ?`),
		now, now, id, owner)
	if err != nil {
		return fmt.Errorf("store: marking %s sent: %w", id, err)
	}
	return requireOneRow(res, "lease on message "+id)
}

// Failure describes why a delivery attempt did not succeed.
type Failure struct {
	// Code is the upstream's own code, e.g. an SMTP enhanced status or an HTTP
	// status. It is what an operator matches against Microsoft's documentation.
	Code string
	// Message is the human-readable reason, already stripped of anything secret.
	Message string
	// Permanent means retrying cannot help.
	Permanent bool
}

// Defer records a temporary failure and schedules the next attempt.
func (r *MessageRepo) Defer(ctx context.Context, id, owner string, f Failure, retryAt time.Time) error {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET
			status = 'deferred', attempts = attempts + 1, next_attempt_at = ?,
			last_error = ?, last_error_code = ?, last_error_permanent = ?,
			lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE id = ? AND lease_owner = ?`),
		retryAt.UTC(), f.Message, f.Code, false, now, id, owner)
	if err != nil {
		return fmt.Errorf("store: deferring %s: %w", id, err)
	}
	return requireOneRow(res, "lease on message "+id)
}

// Fail records a final failure: either the upstream rejected the message
// permanently, or it ran out of attempts.
func (r *MessageRepo) Fail(ctx context.Context, id, owner string, f Failure) error {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET
			status = 'failed', attempts = attempts + 1,
			last_error = ?, last_error_code = ?, last_error_permanent = ?,
			lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE id = ? AND lease_owner = ?`),
		f.Message, f.Code, f.Permanent, now, id, owner)
	if err != nil {
		return fmt.Errorf("store: failing %s: %w", id, err)
	}
	return requireOneRow(res, "lease on message "+id)
}

// Requeue puts a message back in the queue, for an operator retrying a failure
// from the admin UI. It clears any lease, so a message stuck in `sending`
// because its worker vanished can be recovered by hand.
func (r *MessageRepo) Requeue(ctx context.Context, id string) error {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET
			status = 'queued', next_attempt_at = ?, updated_at = ?,
			lease_owner = NULL, lease_expires_at = NULL
		WHERE id = ? AND status IN ('failed', 'deferred', 'held', 'sending')`),
		now, now, id)
	if err != nil {
		return fmt.Errorf("store: requeueing %s: %w", id, err)
	}
	return requireOneRow(res, "retryable message "+id)
}

// Hold takes a message out of the delivery rotation without discarding it.
func (r *MessageRepo) Hold(ctx context.Context, id string) error {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET
			status = 'held', updated_at = ?, lease_owner = NULL, lease_expires_at = NULL
		WHERE id = ? AND status IN ('queued', 'deferred', 'failed')`),
		now, id)
	if err != nil {
		return fmt.Errorf("store: holding %s: %w", id, err)
	}
	return requireOneRow(res, "holdable message "+id)
}

// Delete discards a message and its body.
func (r *MessageRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`DELETE FROM messages WHERE id = ?`), id)
	if err != nil {
		return fmt.Errorf("store: deleting %s: %w", id, err)
	}
	return requireOneRow(res, "message "+id)
}

// ReleaseExpiredLeases returns messages whose worker died back to the queue.
//
// Claiming already ignores an expired lease, so this exists to keep the queue
// view honest: without it a message would sit in `sending` until something else
// happened to claim it.
func (r *MessageRepo) ReleaseExpiredLeases(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE messages SET
			status = 'queued', lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
		WHERE status = 'sending' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?`),
		now, now)
	if err != nil {
		return 0, fmt.Errorf("store: releasing expired leases: %w", err)
	}
	return res.RowsAffected()
}

// Purge deletes finished messages older than the given cutoffs, and returns how
// many rows went. Bodies go with them through the foreign key.
func (r *MessageRepo) Purge(ctx context.Context, sentBefore, failedBefore time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		DELETE FROM messages
		WHERE (status = 'sent' AND updated_at < ?)
		   OR (status = 'failed' AND updated_at < ?)`),
		sentBefore.UTC(), failedBefore.UTC())
	if err != nil {
		return 0, fmt.Errorf("store: purging old messages: %w", err)
	}
	return res.RowsAffected()
}

// MessageFilter narrows a queue or history listing.
type MessageFilter struct {
	Status    []MessageStatus
	MailboxID string
	AccountID string
	// Search matches the envelope sender, the From header, or a recipient.
	Search string
	Since  time.Time
	Until  time.Time
	Limit  int
	Offset int
}

// List returns messages matching a filter, newest first.
func (r *MessageRepo) List(ctx context.Context, f MessageFilter) ([]*Message, error) {
	where, args := f.build()

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, f.Offset)

	rows, err := r.db.QueryContext(ctx, r.db.Rebind(
		`SELECT `+messageColumns+` FROM messages`+where+
			` ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing messages: %w", err)
	}
	defer rows.Close()

	var out []*Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning message: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Count returns how many messages match a filter, for pagination.
func (r *MessageRepo) Count(ctx context.Context, f MessageFilter) (int64, error) {
	where, args := f.build()

	var n int64
	err := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT COUNT(*) FROM messages`+where), args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting messages: %w", err)
	}
	return n, nil
}

// CountByStatus returns the number of messages in each status, for the
// dashboard.
func (r *MessageRepo) CountByStatus(ctx context.Context) (map[MessageStatus]int64, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM messages GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("store: counting messages by status: %w", err)
	}
	defer rows.Close()

	out := map[MessageStatus]int64{}
	for rows.Next() {
		var (
			status MessageStatus
			n      int64
		)
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("store: scanning status count: %w", err)
		}
		out[status] = n
	}
	return out, rows.Err()
}

// build turns a filter into a WHERE clause and its arguments.
func (f MessageFilter) build() (where string, args []any) {
	var clauses []string

	if len(f.Status) > 0 {
		placeholders := make([]string, len(f.Status))
		for i, s := range f.Status {
			placeholders[i] = "?"
			args = append(args, s)
		}
		clauses = append(clauses, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if f.MailboxID != "" {
		clauses = append(clauses, "mailbox_id = ?")
		args = append(args, f.MailboxID)
	}
	if f.AccountID != "" {
		clauses = append(clauses, "smtp_account_id = ?")
		args = append(args, f.AccountID)
	}
	if f.Search != "" {
		// LIKE rather than a full-text index: the queue is small, and an
		// operator searching it is looking for one address they already know.
		like := "%" + f.Search + "%"
		clauses = append(clauses, "(envelope_from LIKE ? OR header_from LIKE ? OR recipients LIKE ?)")
		args = append(args, like, like, like)
	}
	if !f.Since.IsZero() {
		clauses = append(clauses, "received_at >= ?")
		args = append(args, f.Since.UTC())
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "received_at <= ?")
		args = append(args, f.Until.UTC())
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
