package adminapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/queue"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// accountResponse is an SMTP account as the API returns it.
//
// The password hash is never included. The password itself is returned exactly
// once, by the endpoints that generate one, and never again.
type accountResponse struct {
	ID               string           `json:"id"`
	Username         string           `json:"username"`
	Description      string           `json:"description,omitempty"`
	DefaultMailboxID string           `json:"defaultMailboxId,omitempty"`
	MailboxIDs       []string         `json:"mailboxIds"`
	MailboxAddresses []string         `json:"mailboxAddresses"`
	AllowedSenders   []string         `json:"allowedSenders"`
	FromPolicy       store.FromPolicy `json:"fromPolicy"`
	AllowCIDRs       []string         `json:"allowCidrs"`
	RateLimitPerMin  *int             `json:"rateLimitPerMin,omitempty"`
	Enabled          bool             `json:"enabled"`
	LastUsedAt       *time.Time       `json:"lastUsedAt,omitempty"`
	ManagedBy        store.ManagedBy  `json:"managedBy"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
}

// createdAccountResponse carries the generated password, which is the only time
// it exists outside the operator's hands.
type createdAccountResponse struct {
	accountResponse
	// Password is shown once. It is not stored in recoverable form, so there is
	// no way to display it again.
	Password string `json:"password,omitempty"`
}

func (s *Server) mountAccounts(r chi.Router) {
	r.Route("/accounts", func(ar chi.Router) {
		ar.With(s.require(adminauth.PermViewConfig)).Get("/", s.handleListAccounts)
		ar.With(s.require(adminauth.PermViewConfig)).Get("/{id}", s.handleGetAccount)

		ar.With(s.require(adminauth.PermManageAccounts)).Post("/", s.handleCreateAccount)
		ar.With(s.require(adminauth.PermManageAccounts)).Patch("/{id}", s.handleUpdateAccount)
		ar.With(s.require(adminauth.PermManageAccounts)).Delete("/{id}", s.handleDeleteAccount)
		ar.With(s.require(adminauth.PermManageAccounts)).Post("/{id}/password", s.handleResetAccountPassword)
	})
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	accounts, err := s.db.Accounts().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	items := make([]accountResponse, 0, len(accounts))
	for _, a := range accounts {
		resp, err := s.toAccountResponse(ctx, a)
		if err != nil {
			s.writeStoreError(w, r, err)
			return
		}
		items = append(items, resp)
	}
	writeJSON(w, http.StatusOK, listResponse[accountResponse]{Items: items, Total: int64(len(items))})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	a, err := s.db.Accounts().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	resp, err := s.toAccountResponse(ctx, a)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) toAccountResponse(ctx context.Context, a *store.SMTPAccount) (accountResponse, error) {
	mailboxes, err := s.db.Mailboxes().ListForAccount(ctx, a.ID)
	if err != nil {
		return accountResponse{}, err
	}
	senders, err := s.db.Accounts().AllowedSenders(ctx, a.ID)
	if err != nil {
		return accountResponse{}, err
	}

	ids := make([]string, 0, len(mailboxes))
	addresses := make([]string, 0, len(mailboxes))
	for _, m := range mailboxes {
		ids = append(ids, m.ID)
		addresses = append(addresses, m.Address)
	}
	patterns := make([]string, 0, len(senders))
	for _, s := range senders {
		patterns = append(patterns, s.Pattern)
	}

	resp := accountResponse{
		ID: a.ID, Username: a.Username, Description: a.Description,
		DefaultMailboxID: a.DefaultMailboxID.String,
		MailboxIDs:       ids, MailboxAddresses: addresses,
		AllowedSenders: patterns, FromPolicy: a.FromPolicy,
		AllowCIDRs: a.AllowCIDRs, Enabled: a.Enabled,
		ManagedBy: a.ManagedBy, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
	}
	if resp.AllowCIDRs == nil {
		resp.AllowCIDRs = []string{}
	}
	if a.RateLimitPerMin.Valid {
		v := int(a.RateLimitPerMin.Int64)
		resp.RateLimitPerMin = &v
	}
	if a.LastUsedAt.Valid {
		resp.LastUsedAt = &a.LastUsedAt.Time
	}
	return resp, nil
}

type accountRequest struct {
	Username    string `json:"username"`
	Description string `json:"description"`
	// Password is optional; one is generated when it is omitted, which is the
	// path most operators should take.
	Password *string `json:"password"`

	DefaultMailboxID *string   `json:"defaultMailboxId"`
	MailboxIDs       *[]string `json:"mailboxIds"`
	AllowedSenders   *[]string `json:"allowedSenders"`
	FromPolicy       string    `json:"fromPolicy"`
	AllowCIDRs       *[]string `json:"allowCidrs"`
	RateLimitPerMin  *int      `json:"rateLimitPerMin"`
	Enabled          *bool     `json:"enabled"`
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req accountRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if fields := validateAccount(req, true); len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	password, generated, passwordErr := passwordFor(req)
	if passwordErr != nil {
		s.writeStoreError(w, r, passwordErr)
		return
	}
	hash, hashErr := appcrypto.HashPassword(password)
	if hashErr != nil {
		s.writeStoreError(w, r, hashErr)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	a := &store.SMTPAccount{
		Username:     strings.TrimSpace(req.Username),
		PasswordHash: hash,
		Description:  strings.TrimSpace(req.Description),
		FromPolicy:   store.FromPolicy(req.FromPolicy),
		Enabled:      true,
	}
	if req.FromPolicy == "" {
		a.FromPolicy = store.FromPolicyReject
	}
	if req.Enabled != nil {
		a.Enabled = *req.Enabled
	}
	if req.DefaultMailboxID != nil {
		a.DefaultMailboxID = store.NullString(*req.DefaultMailboxID)
	}
	if req.AllowCIDRs != nil {
		a.AllowCIDRs = *req.AllowCIDRs
	}
	if req.RateLimitPerMin != nil {
		a.RateLimitPerMin = store.NullInt(*req.RateLimitPerMin)
	}

	if err := s.db.Accounts().Create(ctx, a); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if err := s.applyAccountLinks(ctx, a.ID, req); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "account.create",
		TargetType: "smtp_account", TargetID: a.ID, TargetName: a.Username,
		Details: map[string]any{
			"fromPolicy": string(a.FromPolicy), "passwordGenerated": generated,
			// Masked by the audit writer; recorded so the entry shows a
			// password was set without recording which.
			"password": password,
		},
	})

	resp, err := s.toAccountResponse(ctx, a)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdAccountResponse{accountResponse: resp, Password: password})
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req accountRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	a, getErr := s.db.Accounts().Get(ctx, chi.URLParam(r, "id"))
	if getErr != nil {
		s.writeStoreError(w, r, getErr)
		return
	}
	if a.ManagedBy == store.ManagedByBootstrap {
		writeError(w, http.StatusConflict, CodeImmutable,
			"this account is declared in the bootstrap file; change it there")
		return
	}
	if fields := validateAccount(req, false); len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	changes := map[string]any{}
	if req.Username != "" {
		a.Username = strings.TrimSpace(req.Username)
		changes["username"] = a.Username
	}
	if req.Description != "" {
		a.Description = strings.TrimSpace(req.Description)
	}
	if req.DefaultMailboxID != nil {
		a.DefaultMailboxID = store.NullString(*req.DefaultMailboxID)
		changes["defaultMailboxId"] = *req.DefaultMailboxID
	}
	if req.FromPolicy != "" {
		a.FromPolicy = store.FromPolicy(req.FromPolicy)
		changes["fromPolicy"] = string(a.FromPolicy)
	}
	if req.AllowCIDRs != nil {
		a.AllowCIDRs = *req.AllowCIDRs
		changes["allowCidrs"] = a.AllowCIDRs
	}
	if req.RateLimitPerMin != nil {
		a.RateLimitPerMin = store.NullInt(*req.RateLimitPerMin)
		changes["rateLimitPerMin"] = *req.RateLimitPerMin
	}
	if req.Enabled != nil {
		a.Enabled = *req.Enabled
		changes["enabled"] = a.Enabled
	}

	if err := s.db.Accounts().Update(ctx, a); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if err := s.applyAccountLinks(ctx, a.ID, req); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "account.update",
		TargetType: "smtp_account", TargetID: a.ID, TargetName: a.Username,
		Details: changes,
	})

	resp, respErr := s.toAccountResponse(ctx, a)
	if respErr != nil {
		s.writeStoreError(w, r, respErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// applyAccountLinks writes the mailbox links and allowed senders when the
// request mentions them.
func (s *Server) applyAccountLinks(ctx context.Context, accountID string, req accountRequest) error {
	if req.MailboxIDs != nil {
		if err := s.db.Accounts().SetMailboxes(ctx, accountID, *req.MailboxIDs); err != nil {
			return err
		}
	}
	if req.AllowedSenders != nil {
		if err := s.db.Accounts().SetAllowedSenders(ctx, accountID, *req.AllowedSenders); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	a, err := s.db.Accounts().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if a.ManagedBy == store.ManagedByBootstrap {
		writeError(w, http.StatusConflict, CodeImmutable,
			"this account is declared in the bootstrap file; remove it there")
		return
	}

	if err := s.db.Accounts().Delete(ctx, a.ID); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "account.delete",
		TargetType: "smtp_account", TargetID: a.ID, TargetName: a.Username,
	})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleResetAccountPassword(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req struct {
		Password *string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	a, err := s.db.Accounts().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	password, generated, passwordErr := passwordFor(accountRequest{Password: req.Password})
	if passwordErr != nil {
		s.writeStoreError(w, r, passwordErr)
		return
	}
	hash, hashErr := appcrypto.HashPassword(password)
	if hashErr != nil {
		s.writeStoreError(w, r, hashErr)
		return
	}

	a.PasswordHash = hash
	if err := s.db.Accounts().Update(ctx, a); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "account.reset_password",
		TargetType: "smtp_account", TargetID: a.ID, TargetName: a.Username,
		Details: map[string]any{"passwordGenerated": generated},
	})

	// Shown once. The device has to be reconfigured with it now, because it
	// cannot be displayed again.
	writeJSON(w, http.StatusOK, map[string]string{"password": password})
}

// passwordFor returns the password to use, generating one when none was given.
func passwordFor(req accountRequest) (password string, generated bool, err error) {
	if req.Password != nil && *req.Password != "" {
		return *req.Password, false, nil
	}
	// Devices vary in what they accept in a password field, so a generated one
	// sticks to an alphabet they all handle.
	generatedPassword, err := appcrypto.GeneratePassword()
	if err != nil {
		return "", false, err
	}
	return generatedPassword, true, nil
}

func validateAccount(req accountRequest, creating bool) map[string]string {
	fields := map[string]string{}

	if creating && strings.TrimSpace(req.Username) == "" {
		fields["username"] = "required"
	}
	if req.Password != nil && *req.Password != "" && len(*req.Password) < 8 {
		// Lower than the admin minimum on purpose: some devices cap what they
		// will store, and this password is scoped to one service on a LAN.
		fields["password"] = "must be at least 8 characters"
	}

	if req.FromPolicy != "" {
		switch store.FromPolicy(req.FromPolicy) {
		case store.FromPolicyReject, store.FromPolicyRewrite, store.FromPolicyPassthrough:
		default:
			fields["fromPolicy"] = "must be reject, rewrite or passthrough"
		}
	}

	if req.AllowedSenders != nil {
		for _, pattern := range *req.AllowedSenders {
			if err := policy.ValidatePattern(pattern); err != nil {
				fields["allowedSenders"] = err.Error()
				break
			}
		}
	}
	if req.AllowCIDRs != nil {
		for _, cidr := range *req.AllowCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				fields["allowCidrs"] = cidr + " is not a CIDR (use /32 for a single address)"
				break
			}
		}
	}
	if req.RateLimitPerMin != nil {
		switch {
		case *req.RateLimitPerMin < 0:
			fields["rateLimitPerMin"] = "must not be negative"
		case *req.RateLimitPerMin > queue.ExchangeMessagesPerMinute:
			fields["rateLimitPerMin"] = "Exchange Online allows at most 30 messages per minute per mailbox"
		}
	}
	return fields
}
