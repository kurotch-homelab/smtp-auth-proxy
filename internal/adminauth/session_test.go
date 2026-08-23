package adminauth_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func newSessionManager(t *testing.T, cfg adminauth.SessionConfig) (*adminauth.SessionManager, *store.DB) {
	t.Helper()

	db := storetest.Open(t, store.DriverSQLite)
	return adminauth.NewSessionManager(db, cfg), db
}

func requestWithCookie(m *adminauth.SessionManager, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/status", http.NoBody)
	if token != "" {
		r.AddCookie(m.Cookie(token, time.Now().Add(time.Hour)))
	}
	return r
}

func TestSessionIssueAndAuthenticate(t *testing.T) {
	t.Parallel()

	m, db := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour, IdleTimeout: time.Hour, Secure: true})
	user := seedAdmin(t, db, "alice", nil)

	issued, err := m.Issue(t.Context(), user, httptest.NewRequest(http.MethodPost, "/login", http.NoBody))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.Token == "" || issued.CSRFToken == "" {
		t.Fatal("Issue returned an empty token")
	}
	if issued.Token == issued.CSRFToken {
		t.Error("the session and CSRF tokens are the same value")
	}

	auth, err := m.Authenticate(t.Context(), requestWithCookie(m, issued.Token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if auth.User.ID != user.ID {
		t.Errorf("Authenticate returned %+v", auth.User)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	t.Parallel()

	m, _ := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour, Secure: true, CookieName: "sap_session"})
	c := m.Cookie("the-token", time.Now().Add(time.Hour))

	// HttpOnly keeps the token out of reach of any script on the page, so a
	// cross-site scripting bug cannot walk off with a session.
	if !c.HttpOnly {
		t.Error("the session cookie is not HttpOnly")
	}
	if !c.Secure {
		t.Error("the session cookie is not Secure")
	}
	// Lax rather than Strict: the identity provider redirects back with a
	// top-level GET, and Strict would drop the cookie on that navigation.
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}

	cleared := m.ClearCookie()
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Errorf("ClearCookie = %+v, want an immediate expiry", cleared)
	}
}

func TestAuthenticateRejections(t *testing.T) {
	t.Parallel()

	m, db := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour, IdleTimeout: time.Hour})
	user := seedAdmin(t, db, "alice", nil)

	issued, err := m.Issue(t.Context(), user, httptest.NewRequest(http.MethodPost, "/login", http.NoBody))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	t.Run("no cookie", func(t *testing.T) {
		t.Parallel()
		if _, err := m.Authenticate(t.Context(), requestWithCookie(m, "")); !errors.Is(err, adminauth.ErrNoSession) {
			t.Errorf("Authenticate = %v, want ErrNoSession", err)
		}
	})

	t.Run("unknown token", func(t *testing.T) {
		t.Parallel()
		if _, err := m.Authenticate(t.Context(), requestWithCookie(m, "not-a-real-token")); !errors.Is(err, adminauth.ErrNoSession) {
			t.Errorf("Authenticate = %v, want ErrNoSession", err)
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		if err := m.Revoke(t.Context(), issued.Session.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if _, err := m.Authenticate(t.Context(), requestWithCookie(m, issued.Token)); !errors.Is(err, adminauth.ErrNoSession) {
			t.Errorf("Authenticate after Revoke = %v, want ErrNoSession", err)
		}
	})
}

func TestCSRF(t *testing.T) {
	t.Parallel()

	m, db := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour, IdleTimeout: time.Hour})
	user := seedAdmin(t, db, "alice", nil)

	issued, err := m.Issue(t.Context(), user, httptest.NewRequest(http.MethodPost, "/login", http.NoBody))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	auth := &store.Authenticated{Session: issued.Session, User: user}

	tests := []struct {
		name    string
		method  string
		token   string
		wantErr bool
	}{
		// A read cannot change anything, so it needs no token.
		{name: "GET needs no token", method: http.MethodGet},
		{name: "HEAD needs no token", method: http.MethodHead},
		{name: "OPTIONS needs no token", method: http.MethodOptions},

		{name: "POST with the right token", method: http.MethodPost, token: issued.CSRFToken},
		{name: "PUT with the right token", method: http.MethodPut, token: issued.CSRFToken},

		{name: "POST with no token", method: http.MethodPost, wantErr: true},
		{name: "POST with the wrong token", method: http.MethodPost, token: "wrong", wantErr: true},
		// The session token is not the CSRF token; using one for the other
		// would defeat the point, since the cookie is sent automatically.
		{name: "POST with the session token", method: http.MethodPost, token: issued.Token, wantErr: true},
		{name: "DELETE with no token", method: http.MethodDelete, wantErr: true},
		{name: "PATCH with no token", method: http.MethodPatch, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(tt.method, "/api/v1/mailboxes", http.NoBody)
			if tt.token != "" {
				r.Header.Set(adminauth.CSRFHeader, tt.token)
			}

			err := m.CheckCSRF(auth, r)
			if tt.wantErr && !errors.Is(err, adminauth.ErrCSRF) {
				t.Errorf("CheckCSRF = %v, want ErrCSRF", err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckCSRF = %v, want nil", err)
			}
		})
	}
}

func TestRevokeAllForUser(t *testing.T) {
	t.Parallel()

	m, db := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour, IdleTimeout: time.Hour})
	user := seedAdmin(t, db, "alice", nil)

	var tokens []string
	for range 3 {
		issued, err := m.Issue(t.Context(), user, httptest.NewRequest(http.MethodPost, "/login", http.NoBody))
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		tokens = append(tokens, issued.Token)
	}

	if err := m.RevokeAllForUser(t.Context(), user.ID); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	for i, token := range tokens {
		if _, err := m.Authenticate(t.Context(), requestWithCookie(m, token)); !errors.Is(err, adminauth.ErrNoSession) {
			t.Errorf("session %d survived: %v", i, err)
		}
	}
}

func TestClientIP(t *testing.T) {
	t.Parallel()

	trusted, err := adminauth.ParseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		trusted    []*net.IPNet
		want       string
	}{
		{
			name:       "no trusted proxies means the header is ignored",
			remoteAddr: "10.0.0.1:5000", forwarded: "203.0.113.9",
			want: "10.0.0.1",
		},
		{
			name:       "a trusted proxy's header is believed",
			remoteAddr: "10.0.0.1:5000", forwarded: "203.0.113.9",
			trusted: trusted, want: "203.0.113.9",
		},
		{
			// Believing it from anywhere would let any client write whatever it
			// liked into the audit log and dodge login rate limiting.
			name:       "an untrusted peer's header is ignored",
			remoteAddr: "203.0.113.1:5000", forwarded: "10.0.0.99",
			trusted: trusted, want: "203.0.113.1",
		},
		{
			name:       "the left-most entry is the original client",
			remoteAddr: "10.0.0.1:5000", forwarded: "203.0.113.9, 10.0.0.2, 10.0.0.1",
			trusted: trusted, want: "203.0.113.9",
		},
		{
			name:       "a malformed header falls back to the peer",
			remoteAddr: "10.0.0.1:5000", forwarded: "not-an-ip",
			trusted: trusted, want: "10.0.0.1",
		},
		{
			name:       "no header at all",
			remoteAddr: "10.0.0.1:5000",
			trusted:    trusted, want: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.forwarded)
			}

			if got := adminauth.ClientIP(r, tt.trusted); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseTrustedProxiesRejectsGarbage(t *testing.T) {
	t.Parallel()

	if _, err := adminauth.ParseTrustedProxies([]string{"not-a-cidr"}); err == nil {
		t.Error("ParseTrustedProxies accepted a malformed CIDR")
	}
	// A bare address is a common mistake; it must be reported rather than
	// silently ignored.
	if _, err := adminauth.ParseTrustedProxies([]string{"10.0.0.1"}); err == nil {
		t.Error("ParseTrustedProxies accepted a bare address")
	}
}

func TestSessionManagerDefaults(t *testing.T) {
	t.Parallel()

	// An empty configuration has to produce something usable rather than a
	// cookie with no name and a zero lifetime.
	m, db := newSessionManager(t, adminauth.SessionConfig{})
	user := seedAdmin(t, db, "alice", nil)

	if m.Lifetime() <= 0 {
		t.Errorf("Lifetime() = %v, want a sensible default", m.Lifetime())
	}
	c := m.Cookie("token", time.Now().Add(time.Hour))
	if c.Name == "" || c.Path == "" {
		t.Errorf("the default cookie is unusable: %+v", c)
	}

	issued, err := m.Issue(t.Context(), user, httptest.NewRequest(http.MethodPost, "/login", http.NoBody))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !issued.Session.ExpiresAt.After(time.Now()) {
		t.Error("the default lifetime produced an already-expired session")
	}
}

func TestIssueRecordsTheClientAndAgent(t *testing.T) {
	t.Parallel()

	m, db := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour})
	user := seedAdmin(t, db, "alice", nil)

	r := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
	r.RemoteAddr = "10.0.0.7:5000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (test)")

	issued, err := m.Issue(t.Context(), user, r)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Somebody reviewing their own sessions needs to be able to tell them apart.
	if issued.Session.IP != "10.0.0.7" {
		t.Errorf("IP = %q, want the client address", issued.Session.IP)
	}
	if issued.Session.UserAgent != "Mozilla/5.0 (test)" {
		t.Errorf("UserAgent = %q", issued.Session.UserAgent)
	}
}

func TestIssueTruncatesAnAbsurdUserAgent(t *testing.T) {
	t.Parallel()

	m, db := newSessionManager(t, adminauth.SessionConfig{Lifetime: time.Hour})
	user := seedAdmin(t, db, "alice", nil)

	r := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
	r.Header.Set("User-Agent", strings.Repeat("A", 4096))

	issued, err := m.Issue(t.Context(), user, r)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(issued.Session.UserAgent) > 512 {
		t.Errorf("UserAgent is %d bytes; an unauthenticated client should not choose how much we store",
			len(issued.Session.UserAgent))
	}
}

func TestStateCookie(t *testing.T) {
	t.Parallel()

	c := adminauth.StateCookie("sap_oidc", "the-state", true)

	if !c.HttpOnly || !c.Secure {
		t.Errorf("the state cookie is not protected: %+v", c)
	}
	// The identity provider redirects back with a top-level GET, which Strict
	// would drop.
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	// Scoped to the callback so it is not sent with every other request.
	if c.Path != adminauth.CallbackPath {
		t.Errorf("Path = %q, want the callback path", c.Path)
	}
	// Short-lived: a pending sign-in that is never completed should not linger.
	if c.MaxAge <= 0 || c.MaxAge > 1800 {
		t.Errorf("MaxAge = %d, want a short positive lifetime", c.MaxAge)
	}
}

func TestClientIPWithAnUnparseableRemoteAddress(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "not-an-address"
	// It must not panic, whatever the transport handed us.
	if got := adminauth.ClientIP(r, nil); got == "" {
		t.Error("ClientIP returned nothing")
	}
}
