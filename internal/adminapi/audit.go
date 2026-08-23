package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// auditEntry is what a handler describes; the writer fills in the rest from the
// request.
type auditEntry struct {
	// Actor is who did it. Nil for an attempt that never authenticated.
	Actor  *store.AdminUser
	Action string

	TargetType string
	TargetID   string
	TargetName string

	// Details is masked before it is written; see store.MaskSecrets.
	Details map[string]any
	// Result defaults to success.
	Result string
}

// audit appends an entry.
//
// A failure to write the audit log is logged but does not fail the request:
// refusing an operator's change because the record of it could not be written
// would be worse than the gap, and the gap is visible in the log.
func (s *Server) audit(ctx context.Context, r *http.Request, e auditEntry) {
	entry := &store.AuditEntry{
		ActorType:  store.ActorSystem,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		TargetName: e.TargetName,
		Result:     e.Result,
		IP:         adminauth.ClientIP(r, s.trustedProxies),
		UserAgent:  truncate(r.UserAgent(), 512),
	}
	if e.Actor != nil {
		entry.ActorType = store.ActorUser
		entry.ActorID = e.Actor.ID
		entry.ActorName = e.Actor.Username
	}
	if len(e.Details) > 0 {
		entry.Details = store.MaskSecrets(e.Details)
	}

	if err := s.db.Audit().Append(ctx, entry); err != nil {
		s.logger(r).Error("could not write an audit entry",
			"action", e.Action, "target", e.TargetID, "reason", err)
	}
}

// auditResponse is one entry as the API returns it.
type auditResponse struct {
	ID         string `json:"id"`
	At         string `json:"at"`
	ActorType  string `json:"actorType"`
	ActorID    string `json:"actorId,omitempty"`
	ActorName  string `json:"actorName,omitempty"`
	Action     string `json:"action"`
	TargetType string `json:"targetType,omitempty"`
	TargetID   string `json:"targetId,omitempty"`
	TargetName string `json:"targetName,omitempty"`
	Details    string `json:"details"`
	Result     string `json:"result"`
	IP         string `json:"ip,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
}

func (s *Server) mountAudit(r chi.Router) {
	r.Route("/audit", func(ar chi.Router) {
		ar.Use(s.require(adminauth.PermViewAudit))
		ar.Get("/", s.handleListAudit)
	})
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	filter := store.AuditFilter{
		ActorID:    r.URL.Query().Get("actorId"),
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("targetType"),
		TargetID:   r.URL.Query().Get("targetId"),
		Limit:      queryInt(r, "limit", 100),
		Offset:     queryInt(r, "offset", 0),
	}
	if since, ok := queryTime(r, "since"); ok {
		filter.Since = since
	}
	if until, ok := queryTime(r, "until"); ok {
		filter.Until = until
	}

	entries, err := s.db.Audit().List(ctx, filter)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	total, err := s.db.Audit().Count(ctx, filter)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	items := make([]auditResponse, 0, len(entries))
	for _, e := range entries {
		items = append(items, auditResponse{
			ID: e.ID, At: e.At.Format(time.RFC3339), ActorType: e.ActorType,
			ActorID: e.ActorID, ActorName: e.ActorName, Action: e.Action,
			TargetType: e.TargetType, TargetID: e.TargetID, TargetName: e.TargetName,
			Details: e.Details, Result: e.Result, IP: e.IP, UserAgent: e.UserAgent,
		})
	}

	writeJSON(w, http.StatusOK, listResponse[auditResponse]{Items: items, Total: total})
}
