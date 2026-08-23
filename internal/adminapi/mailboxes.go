package adminapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/queue"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// mailboxResponse is a shared mailbox as the API returns it.
type mailboxResponse struct {
	ID                string          `json:"id"`
	Address           string          `json:"address"`
	DisplayName       string          `json:"displayName,omitempty"`
	OAuthCredentialID string          `json:"oauthCredentialId"`
	CredentialName    string          `json:"credentialName,omitempty"`
	Transport         store.Transport `json:"transport"`
	// A null limit means "inherit the global default", which is different from
	// a limit of zero, so these are pointers.
	RateLimitPerMin *int            `json:"rateLimitPerMin,omitempty"`
	MaxConcurrent   *int            `json:"maxConcurrent,omitempty"`
	Enabled         bool            `json:"enabled"`
	ManagedBy       store.ManagedBy `json:"managedBy"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

func toMailboxResponse(m *store.Mailbox, credentialName string) mailboxResponse {
	resp := mailboxResponse{
		ID: m.ID, Address: m.Address, DisplayName: m.DisplayName,
		OAuthCredentialID: m.OAuthCredentialID, CredentialName: credentialName,
		Transport: m.Transport, Enabled: m.Enabled, ManagedBy: m.ManagedBy,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
	if m.RateLimitPerMin.Valid {
		v := int(m.RateLimitPerMin.Int64)
		resp.RateLimitPerMin = &v
	}
	if m.MaxConcurrent.Valid {
		v := int(m.MaxConcurrent.Int64)
		resp.MaxConcurrent = &v
	}
	return resp
}

func (s *Server) mountMailboxes(r chi.Router) {
	r.Route("/mailboxes", func(mr chi.Router) {
		mr.With(s.require(adminauth.PermViewConfig)).Get("/", s.handleListMailboxes)
		mr.With(s.require(adminauth.PermViewConfig)).Get("/{id}", s.handleGetMailbox)

		mr.With(s.require(adminauth.PermManageMailboxes)).Post("/", s.handleCreateMailbox)
		mr.With(s.require(adminauth.PermManageMailboxes)).Patch("/{id}", s.handleUpdateMailbox)
		mr.With(s.require(adminauth.PermManageMailboxes)).Delete("/{id}", s.handleDeleteMailbox)
		mr.With(s.require(adminauth.PermManageMailboxes)).Post("/{id}/test", s.handleTestMailbox)
	})
}

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	mailboxes, err := s.db.Mailboxes().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	names := s.credentialNames(ctx)

	items := make([]mailboxResponse, 0, len(mailboxes))
	for _, m := range mailboxes {
		items = append(items, toMailboxResponse(m, names[m.OAuthCredentialID]))
	}
	writeJSON(w, http.StatusOK, listResponse[mailboxResponse]{Items: items, Total: int64(len(items))})
}

func (s *Server) handleGetMailbox(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m, err := s.db.Mailboxes().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toMailboxResponse(m, s.credentialNames(ctx)[m.OAuthCredentialID]))
}

type mailboxRequest struct {
	Address           string `json:"address"`
	DisplayName       string `json:"displayName"`
	OAuthCredentialID string `json:"oauthCredentialId"`
	Transport         string `json:"transport"`
	RateLimitPerMin   *int   `json:"rateLimitPerMin"`
	MaxConcurrent     *int   `json:"maxConcurrent"`
	Enabled           *bool  `json:"enabled"`
}

func (s *Server) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req mailboxRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if fields := validateMailbox(req, true); len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m := &store.Mailbox{
		Address:           strings.ToLower(strings.TrimSpace(req.Address)),
		DisplayName:       strings.TrimSpace(req.DisplayName),
		OAuthCredentialID: req.OAuthCredentialID,
		Transport:         store.Transport(req.Transport),
		Enabled:           true,
	}
	if req.Enabled != nil {
		m.Enabled = *req.Enabled
	}
	if req.RateLimitPerMin != nil {
		m.RateLimitPerMin = store.NullInt(*req.RateLimitPerMin)
	}
	if req.MaxConcurrent != nil {
		m.MaxConcurrent = store.NullInt(*req.MaxConcurrent)
	}

	if err := s.db.Mailboxes().Create(ctx, m); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "mailbox.create",
		TargetType: "mailbox", TargetID: m.ID, TargetName: m.Address,
		Details: map[string]any{"transport": string(m.Transport), "credentialId": m.OAuthCredentialID},
	})

	writeJSON(w, http.StatusCreated, toMailboxResponse(m, s.credentialNames(ctx)[m.OAuthCredentialID]))
}

func (s *Server) handleUpdateMailbox(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req mailboxRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m, err := s.db.Mailboxes().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if m.ManagedBy == store.ManagedByBootstrap {
		writeError(w, http.StatusConflict, CodeImmutable,
			"this mailbox is declared in the bootstrap file; change it there")
		return
	}
	if fields := validateMailbox(req, false); len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	changes := map[string]any{}
	if req.Address != "" {
		m.Address = strings.ToLower(strings.TrimSpace(req.Address))
		changes["address"] = m.Address
	}
	if req.DisplayName != "" {
		m.DisplayName = strings.TrimSpace(req.DisplayName)
	}
	if req.OAuthCredentialID != "" {
		m.OAuthCredentialID = req.OAuthCredentialID
		changes["credentialId"] = m.OAuthCredentialID
	}
	if req.Transport != "" {
		m.Transport = store.Transport(req.Transport)
		changes["transport"] = string(m.Transport)
	}
	if req.RateLimitPerMin != nil {
		m.RateLimitPerMin = store.NullInt(*req.RateLimitPerMin)
		changes["rateLimitPerMin"] = *req.RateLimitPerMin
	}
	if req.MaxConcurrent != nil {
		m.MaxConcurrent = store.NullInt(*req.MaxConcurrent)
		changes["maxConcurrent"] = *req.MaxConcurrent
	}
	if req.Enabled != nil {
		m.Enabled = *req.Enabled
		changes["enabled"] = m.Enabled
	}

	if err := s.db.Mailboxes().Update(ctx, m); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "mailbox.update",
		TargetType: "mailbox", TargetID: m.ID, TargetName: m.Address,
		Details: changes,
	})
	writeJSON(w, http.StatusOK, toMailboxResponse(m, s.credentialNames(ctx)[m.OAuthCredentialID]))
}

func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	m, err := s.db.Mailboxes().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if m.ManagedBy == store.ManagedByBootstrap {
		writeError(w, http.StatusConflict, CodeImmutable,
			"this mailbox is declared in the bootstrap file; remove it there")
		return
	}

	if err := s.db.Mailboxes().Delete(ctx, m.ID); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "mailbox.delete",
		TargetType: "mailbox", TargetID: m.ID, TargetName: m.Address,
	})
	writeJSON(w, http.StatusNoContent, nil)
}

// testResponse reports whether a mailbox can actually authenticate.
type testResponse struct {
	OK bool `json:"ok"`
	// Stage is where it got to: "token" or "authenticate".
	Stage   string `json:"stage"`
	Message string `json:"message"`
	// Hint is what to do about a failure, when there is something useful to say.
	Hint string `json:"hint,omitempty"`
}

// handleTestMailbox acquires a token for a mailbox without sending anything.
//
// It is the difference between "the configuration looks right" and "Microsoft
// 365 accepts it", which is otherwise only discovered when the first message
// fails.
func (s *Server) handleTestMailbox(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	if s.tokens == nil {
		writeError(w, http.StatusServiceUnavailable, CodeInternal,
			"the token provider is not available")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	m, err := s.db.Mailboxes().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	credential, err := s.db.Credentials().Get(ctx, m.OAuthCredentialID)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	scope := s.scopeFor(m.Transport)
	result := testResponse{Stage: "token"}

	if _, err := s.tokens.Token(ctx, credential, scope); err != nil {
		result.Message = err.Error()
		result.Hint = "Check that the client secret or certificate is current, and that the " +
			"tenant and client IDs match the application registration."
	} else {
		result.OK = true
		result.Stage = "token"
		result.Message = "Microsoft Entra issued an access token for this credential."
		result.Hint = "A token only proves the application registration works. If mail still " +
			"fails with 535, the missing piece is usually the Exchange side: admin consent for " +
			"SMTP.SendAsApp, New-ServicePrincipal, or Add-MailboxPermission for this mailbox."
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "mailbox.test",
		TargetType: "mailbox", TargetID: m.ID, TargetName: m.Address,
		Result:  resultFor(result.OK),
		Details: map[string]any{"scope": scope, "ok": result.OK},
	})

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) scopeFor(transport store.Transport) string {
	if transport == store.TransportGraph {
		return s.graphScope
	}
	return s.smtpScope
}

func resultFor(ok bool) string {
	if ok {
		return store.ResultSuccess
	}
	return store.ResultFailure
}

func (s *Server) credentialNames(ctx context.Context) map[string]string {
	names := map[string]string{}
	credentials, err := s.db.Credentials().List(ctx)
	if err != nil {
		return names
	}
	for _, c := range credentials {
		names[c.ID] = c.Name
	}
	return names
}

func validateMailbox(req mailboxRequest, creating bool) map[string]string {
	fields := map[string]string{}

	if creating || req.Address != "" {
		address := strings.TrimSpace(req.Address)
		if address == "" {
			fields["address"] = "required"
		} else if _, err := policy.ParseAddress(address); err != nil {
			fields["address"] = "must be a valid email address"
		}
	}
	if creating && strings.TrimSpace(req.OAuthCredentialID) == "" {
		fields["oauthCredentialId"] = "required"
	}

	if req.Transport != "" {
		switch store.Transport(req.Transport) {
		case store.TransportSMTP, store.TransportGraph:
		default:
			fields["transport"] = "must be smtp or graph"
		}
	} else if creating {
		fields["transport"] = "required"
	}

	// Exchange Online will not honor a budget above its own limits; it just
	// answers "4.7.500 Server busy", so the value is refused here where the
	// reason can be explained.
	if req.RateLimitPerMin != nil {
		switch {
		case *req.RateLimitPerMin < 0:
			fields["rateLimitPerMin"] = "must not be negative"
		case *req.RateLimitPerMin > queue.ExchangeMessagesPerMinute:
			fields["rateLimitPerMin"] = "Exchange Online allows at most 30 messages per minute per mailbox"
		}
	}
	if req.MaxConcurrent != nil {
		switch {
		case *req.MaxConcurrent < 0:
			fields["maxConcurrent"] = "must not be negative"
		case *req.MaxConcurrent > queue.ExchangeConcurrentConnections:
			fields["maxConcurrent"] = "Exchange Online allows at most 3 concurrent connections per mailbox"
		}
	}
	return fields
}
