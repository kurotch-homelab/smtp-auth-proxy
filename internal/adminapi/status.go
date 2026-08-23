package adminapi

import (
	"context"
	"net/http"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/version"
)

// statusResponse is what the dashboard renders.
type statusResponse struct {
	Version string `json:"version"`
	// QueueByStatus counts messages in each state.
	QueueByStatus map[store.MessageStatus]int64 `json:"queueByStatus"`

	Mailboxes   int `json:"mailboxes"`
	Accounts    int `json:"accounts"`
	Credentials int `json:"credentials"`

	// ExpiringCredentials are the ones that stop working soon. A client secret
	// quietly expiring is the most common way a working deployment breaks.
	ExpiringCredentials []expiringCredential `json:"expiringCredentials"`

	// RecentFailures surfaces what is going wrong right now, so the dashboard
	// answers "is anything broken" without a search.
	RecentFailures []messageResponse `json:"recentFailures"`

	// AuthFailureCount counts deliveries refused by Microsoft 365 in the last
	// day, which almost always means a tenant setting rather than a bad message.
	AuthFailureCount int64 `json:"authFailureCount"`
}

type expiringCredential struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	ExpiresAt     time.Time `json:"expiresAt"`
	ExpiresInDays int       `json:"expiresInDays"`
}

// expiryWarningWindow is how far ahead the dashboard warns.
const expiryWarningWindow = 30 * 24 * time.Hour

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp := statusResponse{
		Version:             version.Get().Version,
		ExpiringCredentials: []expiringCredential{},
		RecentFailures:      []messageResponse{},
	}

	counts, err := s.db.Messages().CountByStatus(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	resp.QueueByStatus = counts

	mailboxes, err := s.db.Mailboxes().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	resp.Mailboxes = len(mailboxes)

	accounts, err := s.db.Accounts().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	resp.Accounts = len(accounts)

	credentials, err := s.db.Credentials().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	resp.Credentials = len(credentials)

	expiring, err := s.db.Credentials().ExpiringBefore(ctx, time.Now().Add(expiryWarningWindow))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	for _, c := range expiring {
		resp.ExpiringCredentials = append(resp.ExpiringCredentials, expiringCredential{
			ID: c.ID, Name: c.Name, ExpiresAt: c.ExpiresAt.Time,
			ExpiresInDays: int(time.Until(c.ExpiresAt.Time).Hours() / 24),
		})
	}

	failures, err := s.db.Messages().List(ctx, store.MessageFilter{
		Status: []store.MessageStatus{store.StatusFailed, store.StatusDeferred},
		Limit:  10,
	})
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	for _, m := range failures {
		resp.RecentFailures = append(resp.RecentFailures, toMessageResponse(m))
	}

	writeJSON(w, http.StatusOK, resp)
}
