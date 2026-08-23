package adminapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminapi"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

const adminPassword = "correct horse battery staple"

// harness is a running API server plus its database.
type harness struct {
	t        *testing.T
	server   *adminapi.Server
	db       *store.DB
	sessions *adminauth.SessionManager
	keyring  *appcrypto.Keyring
}

// harnessOption customizes the server under test.
type harnessOption func(*adminapi.Options)

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()

	db := storetest.Open(t, store.DriverSQLite)

	spec, err := appcrypto.GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyring, err := appcrypto.NewKeyring(spec)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sessions := adminauth.NewSessionManager(db, adminauth.SessionConfig{
		Lifetime: time.Hour, IdleTimeout: time.Hour, CookieName: "sap_session",
	})
	local := adminauth.NewLocalAuthenticator(db,
		adminauth.LocalConfig{Enabled: true, LockoutThreshold: 5, LockoutDuration: time.Minute}, log)

	options := adminapi.Options{
		DB:         db,
		Keyring:    keyring,
		Sessions:   sessions,
		Local:      local,
		SMTPScope:  "https://outlook.office365.com/.default",
		GraphScope: "https://graph.microsoft.com/.default",
		Log:        log,
	}
	for _, opt := range opts {
		opt(&options)
	}

	server, err := adminapi.New(options)
	if err != nil {
		t.Fatalf("adminapi.New: %v", err)
	}

	return &harness{t: t, server: server, db: db, sessions: sessions, keyring: keyring}
}

// user creates an admin user with a password.
func (h *harness) user(username string, role store.Role) *store.AdminUser {
	h.t.Helper()

	hash, err := appcrypto.HashPasswordWith(adminPassword, appcrypto.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		h.t.Fatalf("hashing: %v", err)
	}

	u := &store.AdminUser{
		Username: username, Email: username + "@example.com",
		PasswordHash: store.NullString(hash), Role: role, Source: store.SourceLocal,
	}
	if err := h.db.Users().Create(h.t.Context(), u); err != nil {
		h.t.Fatalf("creating %q: %v", username, err)
	}
	return u
}

// session is an authenticated client.
type session struct {
	h         *harness
	token     string
	csrfToken string
	user      *store.AdminUser
}

// signIn issues a session directly, bypassing the login endpoint.
func (h *harness) signIn(user *store.AdminUser) *session {
	h.t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", http.NoBody)
	issued, err := h.sessions.Issue(h.t.Context(), user, r)
	if err != nil {
		h.t.Fatalf("issuing a session: %v", err)
	}
	return &session{h: h, token: issued.Token, csrfToken: issued.CSRFToken, user: user}
}

// do sends a request as this session and returns the response.
func (s *session) do(method, path string, body any) *httptest.ResponseRecorder {
	s.h.t.Helper()
	return s.h.request(method, path, body, s.token, s.csrfToken)
}

// anonymous sends a request with no session.
func (h *harness) anonymous(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.request(method, path, body, "", "")
}

func (h *harness) request(method, path string, body any, token, csrf string) *httptest.ResponseRecorder {
	h.t.Helper()

	var reader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("encoding the request body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	r := httptest.NewRequest(method, path, reader)
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.AddCookie(h.sessions.Cookie(token, time.Now().Add(time.Hour)))
	}
	if csrf != "" {
		r.Header.Set(adminauth.CSRFHeader, csrf)
	}

	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, r)
	return rec
}

// decode reads a JSON response body.
func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()

	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decoding the response (%d): %v\n%s", rec.Code, err, rec.Body.String())
	}
	return v
}

// apiError reads an error response.
func apiError(t *testing.T, rec *httptest.ResponseRecorder) adminapi.APIError {
	t.Helper()
	return decode[adminapi.APIError](t, rec)
}

// seedCredential inserts a credential with a sealed secret.
func (h *harness) seedCredential(name string) *store.OAuthCredential {
	h.t.Helper()

	c := &store.OAuthCredential{
		Name: name, TenantID: "tenant", ClientID: "client",
		AuthType: store.AuthTypeSecret,
	}
	if err := h.db.Credentials().Create(h.t.Context(), c); err != nil {
		h.t.Fatalf("creating a credential: %v", err)
	}
	sealed, err := h.keyring.EncryptString("the-secret", c.SecretContext())
	if err != nil {
		h.t.Fatalf("sealing: %v", err)
	}
	c.ClientSecretEnc = sealed
	if err := h.db.Credentials().Update(h.t.Context(), c); err != nil {
		h.t.Fatalf("storing the sealed secret: %v", err)
	}
	return c
}

func (h *harness) seedMailbox(address, credentialID string) *store.Mailbox {
	h.t.Helper()

	m := &store.Mailbox{
		Address: address, OAuthCredentialID: credentialID,
		Transport: store.TransportSMTP, Enabled: true,
	}
	if err := h.db.Mailboxes().Create(h.t.Context(), m); err != nil {
		h.t.Fatalf("creating a mailbox: %v", err)
	}
	return m
}

func (h *harness) seedAccount(username, mailboxID string) *store.SMTPAccount {
	h.t.Helper()

	a := &store.SMTPAccount{
		Username: username, PasswordHash: "hash",
		DefaultMailboxID: store.NullString(mailboxID),
		FromPolicy:       store.FromPolicyReject, Enabled: true,
	}
	if err := h.db.Accounts().Create(h.t.Context(), a); err != nil {
		h.t.Fatalf("creating an account: %v", err)
	}
	return a
}

func (h *harness) seedMessage(mailbox *store.Mailbox) *store.Message {
	h.t.Helper()

	m := &store.Message{
		MailboxID: store.NullString(mailbox.ID), MailboxAddress: mailbox.Address,
		EnvelopeFrom: mailbox.Address, Recipients: []string{"ops@example.net"},
		NextAttemptAt: time.Now().Add(time.Hour),
	}
	if err := h.db.Messages().Enqueue(h.t.Context(), m, []byte("Subject: test\r\n\r\nbody")); err != nil {
		h.t.Fatalf("enqueueing: %v", err)
	}
	return m
}

// requestWithCookies sends a request carrying arbitrary cookies, for flows that
// depend on one the server set earlier.
func (h *harness) requestWithCookies(method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()

	r := httptest.NewRequest(method, path, http.NoBody)
	for _, c := range cookies {
		r.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, r)
	return rec
}
