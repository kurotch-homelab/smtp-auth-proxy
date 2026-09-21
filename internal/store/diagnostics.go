package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// EnqueueDiagnostic atomically reserves an idempotency key and writes a normal
// queue message. Reservations outlive message deletion, preventing a repeated
// browser request from silently sending again after retention purges the body.
func (r *MessageRepo) EnqueueDiagnostic(ctx context.Context, actorID, requestID, mailboxID, recipient string, m *Message, body []byte) (id string, created bool, resultErr error) {
	resultErr = r.db.InTx(ctx, func(tx *Tx) error {
		res, err := tx.ExecContext(ctx, tx.Rebind(`INSERT INTO diagnostic_requests
			(actor_id, request_id, mailbox_id, recipient, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (actor_id, request_id) DO NOTHING`), actorID, requestID, mailboxID, recipient, time.Now().UTC())
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			var savedMailbox, savedRecipient string
			var savedID sql.NullString
			err = tx.QueryRowContext(ctx, tx.Rebind(`SELECT mailbox_id, recipient, message_id FROM diagnostic_requests WHERE actor_id = ? AND request_id = ?`), actorID, requestID).Scan(&savedMailbox, &savedRecipient, &savedID)
			if err != nil {
				return err
			}
			if savedMailbox != mailboxID || savedRecipient != recipient || !savedID.Valid {
				return ErrStateConflict
			}
			id = savedID.String
			return nil
		}
		// Recheck inside the write transaction, so disable/delete/credential
		// changes cannot race the API's preliminary checks.
		var enabled bool
		var address, credential, authType, secret, certificate, key, transport string
		q := `SELECT m.enabled, m.address, c.id, c.auth_type, c.client_secret_enc, c.certificate_pem, c.certificate_key_enc, m.transport
		 FROM mailboxes m JOIN oauth_credentials c ON c.id = m.oauth_credential_id WHERE m.id = ?`
		if r.db.Dialect().Name() == "postgres" {
			q += ` FOR SHARE OF m, c`
		}
		err = tx.QueryRowContext(ctx, tx.Rebind(q), mailboxID).Scan(&enabled, &address, &credential, &authType, &secret, &certificate, &key, &transport)
		if err != nil {
			return translateError(r.db.Dialect(), err, "diagnostic mailbox")
		}
		if !enabled || address != m.MailboxAddress || (transport != "smtp" && transport != "graph") ||
			(authType == "secret" && secret == "") || (authType == "certificate" && (certificate == "" || key == "")) {
			return ErrStateConflict
		}
		m.Origin = "diagnostic"
		m.SMTPAccountID = sql.NullString{}
		m.AccountUsername = ""
		m.MailboxID = NullString(mailboxID)
		if enqueueErr := r.enqueueTx(ctx, tx, m, body); enqueueErr != nil {
			return enqueueErr
		}
		_, err = tx.ExecContext(ctx, tx.Rebind(`UPDATE diagnostic_requests SET message_id = ? WHERE actor_id = ? AND request_id = ?`), m.ID, actorID, requestID)
		if err != nil {
			return err
		}
		// Sending a test is an audited operation: commit the actor record with
		// the message and reservation so a crash cannot leave an unaudited send.
		actorName := actorID
		var username string
		lookupErr := tx.QueryRowContext(ctx, tx.Rebind(`SELECT username FROM admin_users WHERE id = ?`), actorID).Scan(&username)
		if lookupErr == nil {
			actorName = username
		} else if !errors.Is(lookupErr, sql.ErrNoRows) {
			return lookupErr
		}
		details := MaskSecrets(map[string]any{"messageId": m.ID, "requestId": requestID, "recipient": recipient})
		_, err = tx.ExecContext(ctx, tx.Rebind(`INSERT INTO audit_logs (`+auditColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			NewID(), time.Now().UTC(), ActorUser, actorID, actorName, "mailbox.test_send", "mailbox", mailboxID, address, details, ResultSuccess, "", "")
		id, created = m.ID, true
		return err
	})
	return id, created, resultErr
}
