package adminapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// credentialResponse is an application registration as the API returns it.
//
// The secret and the certificate key are never included in any form — not even
// the sealed ciphertext. There is no reason for a browser to hold either, and
// an API that returns them turns every XSS bug into a credential leak.
type credentialResponse struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	TenantID string         `json:"tenantId"`
	ClientID string         `json:"clientId"`
	AuthType store.AuthType `json:"authType"`
	// HasSecret and CertificateThumbprint let the UI show what is configured
	// without revealing it.
	HasSecret             bool       `json:"hasSecret"`
	CertificateThumbprint string     `json:"certificateThumbprint,omitempty"`
	AuthorityHost         string     `json:"authorityHost,omitempty"`
	ExpiresAt             *time.Time `json:"expiresAt,omitempty"`
	// ExpiresInDays is what the dashboard warns on.
	ExpiresInDays *int            `json:"expiresInDays,omitempty"`
	ManagedBy     store.ManagedBy `json:"managedBy"`
	MailboxCount  int             `json:"mailboxCount"`
	CreatedAt     time.Time       `json:"createdAt"`
	UpdatedAt     time.Time       `json:"updatedAt"`
}

func toCredentialResponse(c *store.OAuthCredential, mailboxes int) credentialResponse {
	resp := credentialResponse{
		ID: c.ID, Name: c.Name, TenantID: c.TenantID, ClientID: c.ClientID,
		AuthType:              c.AuthType,
		HasSecret:             c.ClientSecretEnc != "" || c.CertificateKeyEnc != "",
		CertificateThumbprint: c.CertificateThumbprint,
		AuthorityHost:         c.AuthorityHost,
		ManagedBy:             c.ManagedBy,
		MailboxCount:          mailboxes,
		CreatedAt:             c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
	if c.ExpiresAt.Valid {
		resp.ExpiresAt = &c.ExpiresAt.Time
		days := int(time.Until(c.ExpiresAt.Time).Hours() / 24)
		resp.ExpiresInDays = &days
	}
	return resp
}

func (s *Server) mountCredentials(r chi.Router) {
	r.Route("/credentials", func(cr chi.Router) {
		cr.With(s.require(adminauth.PermViewConfig)).Get("/", s.handleListCredentials)
		cr.With(s.require(adminauth.PermViewConfig)).Get("/{id}", s.handleGetCredential)
		cr.With(s.require(adminauth.PermViewConfig)).Get("/{id}/setup", s.handleCredentialSetup)

		cr.With(s.require(adminauth.PermManageCredentials)).Post("/", s.handleCreateCredential)
		cr.With(s.require(adminauth.PermManageCredentials)).Patch("/{id}", s.handleUpdateCredential)
		cr.With(s.require(adminauth.PermManageCredentials)).Delete("/{id}", s.handleDeleteCredential)
	})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	credentials, err := s.db.Credentials().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	mailboxes, err := s.db.Mailboxes().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	perCredential := map[string]int{}
	for _, mb := range mailboxes {
		perCredential[mb.OAuthCredentialID]++
	}

	items := make([]credentialResponse, 0, len(credentials))
	for _, c := range credentials {
		items = append(items, toCredentialResponse(c, perCredential[c.ID]))
	}
	writeJSON(w, http.StatusOK, listResponse[credentialResponse]{Items: items, Total: int64(len(items))})
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	c, err := s.db.Credentials().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCredentialResponse(c, s.countMailboxes(ctx, c.ID)))
}

func (s *Server) countMailboxes(ctx context.Context, credentialID string) int {
	mailboxes, err := s.db.Mailboxes().List(ctx)
	if err != nil {
		return 0
	}
	n := 0
	for _, mb := range mailboxes {
		if mb.OAuthCredentialID == credentialID {
			n++
		}
	}
	return n
}

type credentialRequest struct {
	Name     string `json:"name"`
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	AuthType string `json:"authType"`

	// ClientSecret, CertificatePEM and CertificateKeyPEM are write-only. An
	// omitted value on an update leaves the stored one alone, so the UI can
	// send back an object it never received the secret for.
	ClientSecret      *string `json:"clientSecret,omitempty"`
	CertificatePEM    *string `json:"certificatePem,omitempty"`
	CertificateKeyPEM *string `json:"certificateKeyPem,omitempty"`

	AuthorityHost string     `json:"authorityHost"`
	ExpiresAt     *time.Time `json:"expiresAt"`
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req credentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	fields := validateCredential(req, true)
	if len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	c := &store.OAuthCredential{
		ID:            store.NewID(),
		Name:          strings.TrimSpace(req.Name),
		TenantID:      strings.TrimSpace(req.TenantID),
		ClientID:      strings.TrimSpace(req.ClientID),
		AuthType:      store.AuthType(req.AuthType),
		AuthorityHost: strings.TrimSpace(req.AuthorityHost),
	}
	if req.ExpiresAt != nil {
		c.ExpiresAt = store.NullTime(*req.ExpiresAt)
	}
	if err := s.sealCredential(c, req); err != nil {
		writeValidationError(w, map[string]string{"clientSecret": err.Error()})
		return
	}

	if err := s.db.Credentials().Create(ctx, c); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "credential.create",
		TargetType: "credential", TargetID: c.ID, TargetName: c.Name,
		Details: map[string]any{
			"tenantId": c.TenantID, "clientId": c.ClientID, "authType": string(c.AuthType),
		},
	})

	writeJSON(w, http.StatusCreated, toCredentialResponse(c, 0))
}

func (s *Server) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req credentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	c, err := s.db.Credentials().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if c.ManagedBy == store.ManagedByBootstrap {
		writeError(w, http.StatusConflict, CodeImmutable,
			"this credential is declared in the bootstrap file; change it there")
		return
	}

	fields := validateCredential(req, false)
	if len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	if req.Name != "" {
		c.Name = strings.TrimSpace(req.Name)
	}
	if req.TenantID != "" {
		c.TenantID = strings.TrimSpace(req.TenantID)
	}
	if req.ClientID != "" {
		c.ClientID = strings.TrimSpace(req.ClientID)
	}
	if req.AuthType != "" {
		c.AuthType = store.AuthType(req.AuthType)
	}
	if req.AuthorityHost != "" {
		c.AuthorityHost = strings.TrimSpace(req.AuthorityHost)
	}
	if req.ExpiresAt != nil {
		c.ExpiresAt = store.NullTime(*req.ExpiresAt)
	}
	if err := s.sealCredential(c, req); err != nil {
		writeValidationError(w, map[string]string{"clientSecret": err.Error()})
		return
	}

	if err := s.db.Credentials().Update(ctx, c); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	// The token provider caches a client per credential; drop it so a rotated
	// secret takes effect on the next delivery rather than after a restart.
	if s.tokens != nil {
		s.tokens.Forget(c.ID)
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "credential.update",
		TargetType: "credential", TargetID: c.ID, TargetName: c.Name,
		Details: map[string]any{
			"tenantId": c.TenantID, "clientId": c.ClientID, "authType": string(c.AuthType),
			"secretChanged": req.ClientSecret != nil || req.CertificateKeyPEM != nil,
		},
	})

	writeJSON(w, http.StatusOK, toCredentialResponse(c, s.countMailboxes(ctx, c.ID)))
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User
	id := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	c, err := s.db.Credentials().Get(ctx, id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if c.ManagedBy == store.ManagedByBootstrap {
		writeError(w, http.StatusConflict, CodeImmutable,
			"this credential is declared in the bootstrap file; remove it there")
		return
	}

	if err := s.db.Credentials().Delete(ctx, id); err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if s.tokens != nil {
		s.tokens.Forget(id)
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "credential.delete",
		TargetType: "credential", TargetID: c.ID, TargetName: c.Name,
	})
	writeJSON(w, http.StatusNoContent, nil)
}

// sealCredential encrypts any newly supplied secret material.
func (s *Server) sealCredential(c *store.OAuthCredential, req credentialRequest) error {
	if s.keyring == nil {
		return errNoKeyring
	}

	if req.ClientSecret != nil {
		sealed, err := s.keyring.EncryptString(*req.ClientSecret, c.SecretContext())
		if err != nil {
			return err
		}
		c.ClientSecretEnc = sealed
	}
	if req.CertificatePEM != nil {
		c.CertificatePEM = *req.CertificatePEM
	}
	if req.CertificateKeyPEM != nil {
		sealed, err := s.keyring.EncryptString(*req.CertificateKeyPEM, c.CertificateKeyContext())
		if err != nil {
			return err
		}
		c.CertificateKeyEnc = sealed
	}
	return nil
}

func validateCredential(req credentialRequest, creating bool) map[string]string {
	fields := map[string]string{}

	if creating {
		if strings.TrimSpace(req.Name) == "" {
			fields["name"] = "required"
		}
		if strings.TrimSpace(req.TenantID) == "" {
			fields["tenantId"] = "required"
		}
		if strings.TrimSpace(req.ClientID) == "" {
			fields["clientId"] = "required"
		}
	}

	if req.AuthType != "" {
		switch store.AuthType(req.AuthType) {
		case store.AuthTypeSecret, store.AuthTypeCertificate:
		default:
			fields["authType"] = "must be secret or certificate"
		}
	} else if creating {
		fields["authType"] = "required"
	}

	if creating {
		switch store.AuthType(req.AuthType) {
		case store.AuthTypeSecret:
			if req.ClientSecret == nil || *req.ClientSecret == "" {
				fields["clientSecret"] = "required for a secret credential"
			}
		case store.AuthTypeCertificate:
			if req.CertificatePEM == nil || *req.CertificatePEM == "" {
				fields["certificatePem"] = "required for a certificate credential"
			}
			if req.CertificateKeyPEM == nil || *req.CertificateKeyPEM == "" {
				fields["certificateKeyPem"] = "required for a certificate credential"
			}
		}
	}

	if req.AuthorityHost != "" && !strings.HasPrefix(req.AuthorityHost, "https://") {
		fields["authorityHost"] = "must start with https://"
	}
	return fields
}

// setupResponse hands the operator the exact PowerShell to run.
//
// An operator has no way to guess that New-ServicePrincipal wants the Object ID
// from Enterprise applications rather than App registrations, and getting it
// wrong produces a 535 with no hint. Generating the commands with their own
// values filled in removes the guesswork.
type setupResponse struct {
	Summary  string   `json:"summary"`
	Steps    []string `json:"steps"`
	Commands string   `json:"commands"`
	Docs     string   `json:"docs"`
}

func (s *Server) handleCredentialSetup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	c, err := s.db.Credentials().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	mailboxes, err := s.db.Mailboxes().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	addresses := make([]string, 0, len(mailboxes))
	for _, mb := range mailboxes {
		if mb.OAuthCredentialID == c.ID {
			addresses = append(addresses, mb.Address)
		}
	}

	writeJSON(w, http.StatusOK, buildSetup(c, addresses))
}

var errNoKeyring = errNoKeyringType{}

type errNoKeyringType struct{}

func (errNoKeyringType) Error() string {
	return "the proxy has no encryption keys configured, so a secret cannot be stored"
}

// oauthScopeForSetup names the scope the instructions mention.
const oauthScopeForSetup = "https://outlook.office365.com/.default"

var _ = oauth.DefaultAuthorityHost
