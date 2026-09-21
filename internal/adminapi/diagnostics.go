package adminapi

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// handleMailboxDiagnostics returns configuration facts, never secret material.
func (s *Server) handleMailboxDiagnostics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	m, err := s.db.Mailboxes().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	c, err := s.db.Credentials().Get(ctx, m.OAuthCredentialID)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	related, err := s.db.Mailboxes().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	count := 0
	for _, mailbox := range related {
		if mailbox.OAuthCredentialID == c.ID {
			count++
		}
	}
	endpoint := s.smtpEndpoint
	if m.Transport == store.TransportGraph {
		endpoint = s.graphEndpoint
	}
	// A configured URL could contain userinfo or query credentials. Only its
	// network destination and path are relevant to this diagnostic.
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Host != "" {
		parsed.User, parsed.RawQuery, parsed.Fragment = nil, "", ""
		endpoint = parsed.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mailbox": toMailboxResponse(m, c.Name), "credential": toCredentialResponse(c, count),
		"endpoint": endpoint, "scope": s.scopeFor(m.Transport),
		"verificationScope": "Token acquisition checks authentication only. A queued test checks Microsoft 365 acceptance, not inbox arrival or device SMTP login.",
	})
}

func (s *Server) handleSendMailboxTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequestID string `json:"requestId"`
		Recipient string `json:"recipient"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	requestID, err := uuid.Parse(req.RequestID)
	if err != nil {
		writeValidationError(w, map[string]string{"requestId": "must be a UUID"})
		return
	}
	address, err := policy.ParseAddress(req.Recipient)
	if err != nil || address.Normalized == "" || strings.ContainsAny(req.Recipient, "\r\n") {
		writeValidationError(w, map[string]string{"recipient": "specify one valid recipient"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	m, err := s.db.Mailboxes().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	from, err := policy.ParseAddress(m.Address)
	if err != nil || from.Normalized == "" {
		writeError(w, http.StatusConflict, CodeConflict, "mailbox address is invalid")
		return
	}
	id := store.NewID()
	messageID := "<" + id + "@smtp-auth-proxy.invalid>"
	const subject = "smtp-auth-proxy diagnostic test"
	body := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nDate: %s\r\nMessage-ID: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThis is a diagnostic test sent through the normal smtp-auth-proxy delivery queue.\r\nMicrosoft 365 acceptance does not prove inbox arrival or device SMTP login.\r\n",
		(&mail.Address{Address: from.Normalized}).String(), (&mail.Address{Address: address.Normalized}).String(), time.Now().UTC().Format(time.RFC1123Z), messageID, subject))
	message := &store.Message{
		ID: id, MailboxAddress: m.Address, EnvelopeFrom: from.Normalized, HeaderFrom: from.Normalized,
		Recipients: []string{address.Normalized}, SizeBytes: int64(len(body)), Subject: subject, MessageID: messageID,
	}
	actor := authFrom(r.Context()).User
	id, created, err := s.db.Messages().EnqueueDiagnostic(ctx, actor.ID, requestID.String(), m.ID, address.Normalized, message, body)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"messageId": id, "created": created})
}
