package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// messageResponse is a queued or delivered message as the API returns it.
//
// The body is not included. It is somebody's mail, and downloading it is a
// separate endpoint behind a separate permission.
type messageResponse struct {
	ID              string   `json:"id"`
	AccountUsername string   `json:"accountUsername,omitempty"`
	MailboxAddress  string   `json:"mailboxAddress,omitempty"`
	EnvelopeFrom    string   `json:"envelopeFrom"`
	HeaderFrom      string   `json:"headerFrom,omitempty"`
	Recipients      []string `json:"recipients"`
	RecipientCount  int      `json:"recipientCount"`
	SizeBytes       int64    `json:"sizeBytes"`
	// Subject is only present when the operator enabled recording it.
	Subject   string              `json:"subject,omitempty"`
	MessageID string              `json:"messageId,omitempty"`
	Status    store.MessageStatus `json:"status"`
	Attempts  int                 `json:"attempts"`

	NextAttemptAt      *time.Time `json:"nextAttemptAt,omitempty"`
	LastError          string     `json:"lastError,omitempty"`
	LastErrorCode      string     `json:"lastErrorCode,omitempty"`
	LastErrorPermanent bool       `json:"lastErrorPermanent"`

	ClientIP   string     `json:"clientIp,omitempty"`
	ReceivedAt time.Time  `json:"receivedAt"`
	SentAt     *time.Time `json:"sentAt,omitempty"`
}

func toMessageResponse(m *store.Message) messageResponse {
	resp := messageResponse{
		ID: m.ID, AccountUsername: m.AccountUsername, MailboxAddress: m.MailboxAddress,
		EnvelopeFrom: m.EnvelopeFrom, HeaderFrom: m.HeaderFrom,
		Recipients: m.Recipients, RecipientCount: m.RecipientCount,
		SizeBytes: m.SizeBytes, Subject: m.Subject, MessageID: m.MessageID,
		Status: m.Status, Attempts: m.Attempts,
		LastError: m.LastError, LastErrorCode: m.LastErrorCode,
		LastErrorPermanent: m.LastErrorPermanent,
		ClientIP:           m.ClientIP, ReceivedAt: m.ReceivedAt,
	}
	if resp.Recipients == nil {
		resp.Recipients = []string{}
	}
	// A retry time only means something while the message is still waiting.
	if m.Status == store.StatusQueued || m.Status == store.StatusDeferred {
		next := m.NextAttemptAt
		resp.NextAttemptAt = &next
	}
	if m.SentAt.Valid {
		resp.SentAt = &m.SentAt.Time
	}
	return resp
}

func (s *Server) mountMessages(r chi.Router) {
	r.Route("/messages", func(mr chi.Router) {
		mr.With(s.require(adminauth.PermViewStatus)).Get("/", s.handleListMessages)
		mr.With(s.require(adminauth.PermViewStatus)).Get("/{id}", s.handleGetMessage)

		// Downloading the body means reading somebody's mail, so it is narrower
		// than working the queue.
		mr.With(s.require(adminauth.PermReadMessageBody)).Get("/{id}/body", s.handleGetMessageBody)

		mr.With(s.require(adminauth.PermManageQueue)).Post("/{id}/retry", s.handleRetryMessage)
		mr.With(s.require(adminauth.PermManageQueue)).Post("/{id}/hold", s.handleHoldMessage)
		mr.With(s.require(adminauth.PermManageQueue)).Delete("/{id}", s.handleDeleteMessage)
	})
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	filter := store.MessageFilter{
		MailboxID: r.URL.Query().Get("mailboxId"),
		AccountID: r.URL.Query().Get("accountId"),
		Search:    r.URL.Query().Get("search"),
		Limit:     queryInt(r, "limit", 50),
		Offset:    queryInt(r, "offset", 0),
	}
	for _, raw := range queryList(r, "status") {
		filter.Status = append(filter.Status, store.MessageStatus(raw))
	}
	if since, ok := queryTime(r, "since"); ok {
		filter.Since = since
	}
	if until, ok := queryTime(r, "until"); ok {
		filter.Until = until
	}

	messages, err := s.db.Messages().List(ctx, filter)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	total, err := s.db.Messages().Count(ctx, filter)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	items := make([]messageResponse, 0, len(messages))
	for _, m := range messages {
		items = append(items, toMessageResponse(m))
	}
	writeJSON(w, http.StatusOK, listResponse[messageResponse]{Items: items, Total: total})
}

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m, err := s.db.Messages().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toMessageResponse(m))
}

func (s *Server) handleGetMessageBody(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User
	id := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m, err := s.db.Messages().Get(ctx, id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	body, err := s.db.Messages().Body(ctx, id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	// Reading somebody's mail is worth its own audit entry, whoever did it.
	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "message.read_body",
		TargetType: "message", TargetID: m.ID, TargetName: m.MailboxAddress,
		Details: map[string]any{"sizeBytes": m.SizeBytes, "recipients": m.RecipientCount},
	})

	// message/rfc822 with an attachment disposition, plus the nosniff header
	// every response carries, means a browser downloads the file rather than
	// rendering whatever HTML the message happens to contain.
	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("Content-Disposition", `attachment; filename="`+m.ID+`.eml"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	//nolint:gosec // G705: the body is served as a download, not as a page; the
	// filename is a generated identifier and the content type is not text/html.
	_, _ = w.Write(body)
}

func (s *Server) handleRetryMessage(w http.ResponseWriter, r *http.Request) {
	s.queueAction(w, r, "message.retry", func(ctx context.Context, id string) error {
		return s.db.Messages().Requeue(ctx, id)
	})
}

func (s *Server) handleHoldMessage(w http.ResponseWriter, r *http.Request) {
	s.queueAction(w, r, "message.hold", func(ctx context.Context, id string) error {
		return s.db.Messages().Hold(ctx, id)
	})
}

func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	s.queueAction(w, r, "message.delete", func(ctx context.Context, id string) error {
		return s.db.Messages().Delete(ctx, id)
	})
}

// queueAction runs one queue operation and records it.
func (s *Server) queueAction(w http.ResponseWriter, r *http.Request, action string, do func(context.Context, string) error) {
	actor := authFrom(r.Context()).User
	id := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m, err := s.db.Messages().Get(ctx, id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if err := do(ctx, id); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: action,
		TargetType: "message", TargetID: m.ID, TargetName: m.MailboxAddress,
		Details: map[string]any{"previousStatus": string(m.Status), "attempts": m.Attempts},
	})
	writeJSON(w, http.StatusNoContent, nil)
}
