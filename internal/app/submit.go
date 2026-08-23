package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// submitter persists an accepted submission for the queue to deliver.
type submitter struct {
	db  *store.DB
	log *slog.Logger
}

// Submit implements smtpsrv.Submitter.
func (s *submitter) Submit(ctx context.Context, sub *smtpsrv.Submission) (string, error) {
	m := &store.Message{
		SMTPAccountID: store.NullString(sub.Identity.AccountID),
		MailboxID:     store.NullString(sub.Mailbox.ID),
		// The username and address are denormalized so the history stays
		// readable after the account or mailbox is deleted.
		AccountUsername: sub.Identity.Username,
		MailboxAddress:  sub.Mailbox.Address,

		// The envelope sender is recorded as the client asked for it; delivery
		// forces it to the mailbox address, and the difference is worth keeping
		// for the audit trail.
		EnvelopeFrom: sub.EnvelopeFrom.Original,
		HeaderFrom:   sub.HeaderFrom.Original,
		Recipients:   sub.Recipients,
		SizeBytes:    int64(len(sub.Raw)),
		Subject:      sub.Subject,
		MessageID:    sub.MessageID,

		ClientIP:   clientIP(sub),
		ReceivedAt: sub.ReceivedAt,
	}

	if err := s.db.Messages().Enqueue(ctx, m, sub.Raw); err != nil {
		return "", fmt.Errorf("queueing a submission from %s: %w", sub.Identity.Username, err)
	}
	return m.ID, nil
}

func clientIP(sub *smtpsrv.Submission) string {
	if sub.ClientIP == nil {
		return ""
	}
	return sub.ClientIP.String()
}
