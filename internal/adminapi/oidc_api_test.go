package adminapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminapi"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/fakeidp"
)

// withOIDC wires single sign-on into the harness against a fake provider.
func withOIDC(t *testing.T, idp *fakeidp.Provider, mutate func(*adminauth.OIDCConfig)) harnessOption {
	t.Helper()

	return func(o *adminapi.Options) {
		cfg := adminauth.OIDCConfig{
			Enabled: true, Issuer: idp.Issuer(),
			ClientID: "smtp-auth-proxy", ClientSecret: "secret",
			Scopes:        []string{"openid", "profile", "email", "groups"},
			BaseURL:       "https://proxy.example.com",
			UsernameClaim: "preferred_username",
			RoleClaim:     "groups",
			RoleMappings:  map[string]string{"sre": "admin"},
			AllowSignup:   true,
		}
		if mutate != nil {
			mutate(&cfg)
		}

		auth, err := adminauth.NewOIDCAuthenticator(t.Context(), cfg, o.DB, idp.Client(), o.Log)
		if err != nil {
			t.Fatalf("NewOIDCAuthenticator: %v", err)
		}
		o.OIDC = auth
		o.OIDCClient = idp.Client()
	}
}

func TestAuthConfigReportsWhatIsAvailable(t *testing.T) {
	t.Parallel()

	// Password only.
	h := newHarness(t)
	body := decode[map[string]any](t, h.anonymous(http.MethodGet, "/api/v1/auth/config", nil))
	if body["localEnabled"] != true || body["oidcEnabled"] != false {
		t.Errorf("config = %v, want local only", body)
	}

	// With single sign-on.
	idp := fakeidp.Start(t)
	withSSO := newHarness(t, withOIDC(t, idp, nil))
	body = decode[map[string]any](t, withSSO.anonymous(http.MethodGet, "/api/v1/auth/config", nil))
	if body["oidcEnabled"] != true {
		t.Errorf("config = %v, want single sign-on advertised", body)
	}
	if body["oidcLabel"] == "" {
		t.Error("the sign-in button has no label")
	}
}

func TestOIDCStartRedirectsToTheProvider(t *testing.T) {
	t.Parallel()

	idp := fakeidp.Start(t)
	h := newHarness(t, withOIDC(t, idp, nil))

	rec := h.anonymous(http.MethodGet, "/api/v1/auth/oidc/start", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("start = %d\n%s", rec.Code, rec.Body.String())
	}

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if !strings.HasPrefix(location.String(), idp.Issuer()) {
		t.Errorf("redirected to %s, want the identity provider", location)
	}
	// PKCE and a nonce on every attempt.
	if location.Query().Get("code_challenge") == "" {
		t.Error("the authorization request carries no PKCE challenge")
	}
	if location.Query().Get("nonce") == "" {
		t.Error("the authorization request carries no nonce")
	}

	// The pending request travels in a short-lived, HttpOnly cookie so the
	// callback need not land on the replica that started it.
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no state cookie was set")
	}
	if !cookies[0].HttpOnly {
		t.Error("the state cookie is not HttpOnly")
	}
}

func TestOIDCStartWithoutConfiguration(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	if rec := h.anonymous(http.MethodGet, "/api/v1/auth/oidc/start", nil); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404 when single sign-on is not configured", rec.Code)
	}
}

func TestOIDCCallbackRejections(t *testing.T) {
	t.Parallel()

	idp := fakeidp.Start(t)
	h := newHarness(t, withOIDC(t, idp, nil))

	tests := []struct {
		name string
		path string
	}{
		// A callback with no pending state cookie: a stale tab, or a replay.
		{name: "no state cookie", path: "/api/v1/auth/oidc/callback?code=x&state=y"},
		// The provider itself refused.
		{name: "provider error", path: "/api/v1/auth/oidc/callback?error=access_denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := h.anonymous(http.MethodGet, tt.path, nil)
			if rec.Code != http.StatusFound {
				t.Fatalf("= %d, want a redirect back to the sign-in page\n%s", rec.Code, rec.Body.String())
			}
			// The browser arrived by a top-level navigation, so it has to be
			// sent somewhere it can render rather than handed JSON.
			location := rec.Header().Get("Location")
			if !strings.HasPrefix(location, "/login?error=") {
				t.Errorf("Location = %q, want the sign-in page with a reason", location)
			}
		})
	}
}

// The whole flow through the API: start, follow the provider, come back.
func TestOIDCSignInEndToEnd(t *testing.T) {
	t.Parallel()

	idp := fakeidp.Start(t)
	idp.SetClaims(map[string]any{
		"sub": "sub-alice", "preferred_username": "alice",
		"email": "alice@example.com", "groups": []any{"sre"},
	})
	h := newHarness(t, withOIDC(t, idp, nil))

	start := h.anonymous(http.MethodGet, "/api/v1/auth/oidc/start", nil)
	if start.Code != http.StatusFound {
		t.Fatalf("start = %d", start.Code)
	}
	stateCookie := start.Result().Cookies()[0]

	// Follow the provider's redirect to get a code and state.
	client := idp.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { client.CheckRedirect = nil }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, start.Header().Get("Location"), http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("following the authorization URL: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing the callback: %v", err)
	}

	// Come back to the proxy with the state cookie the browser would carry.
	rec := h.requestWithCookies(http.MethodGet,
		"/api/v1/auth/oidc/callback?"+callback.RawQuery, stateCookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d\n%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Errorf("Location = %q, want the application", got)
	}

	// A session cookie must have been issued, and the user provisioned.
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sap_session" && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie was issued")
	}

	user, err := h.db.Users().GetBySubject(t.Context(), store.SourceOIDC, "sub-alice")
	if err != nil {
		t.Fatalf("the user was not provisioned: %v", err)
	}
	if user.Role != store.RoleAdmin {
		t.Errorf("role = %q, want the mapped admin", user.Role)
	}
}
