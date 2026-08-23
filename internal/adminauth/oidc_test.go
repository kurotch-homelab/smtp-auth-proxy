package adminauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/fakeidp"
)

// signOn runs the whole flow: start, follow the provider's redirect, and
// complete with the returned code.
func signOn(t *testing.T, a *adminauth.OIDCAuthenticator, idp *fakeidp.Provider) (*store.AdminUser, error) {
	t.Helper()

	req, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Follow the authorization request without following the redirect, so the
	// code and state can be read from the Location header.
	client := idp.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { client.CheckRedirect = nil }()

	resp, err := client.Get(req.URL)
	if err != nil {
		t.Fatalf("following the authorization URL: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	code := location.Query().Get("code")
	returnedState := location.Query().Get("state")
	if code == "" {
		t.Fatalf("the provider returned no code; status %d", resp.StatusCode)
	}

	return a.Complete(context.Background(), code, *req, returnedState, idp.Client())
}

func newOIDC(t *testing.T, mutate func(*adminauth.OIDCConfig)) (*adminauth.OIDCAuthenticator, *fakeidp.Provider, *store.DB) {
	t.Helper()

	idp := fakeidp.Start(t)
	db := storetest.Open(t, store.DriverSQLite)

	cfg := adminauth.OIDCConfig{
		Enabled:       true,
		Issuer:        idp.Issuer(),
		ClientID:      "smtp-auth-proxy",
		ClientSecret:  "client-secret",
		Scopes:        []string{"openid", "profile", "email", "groups"},
		BaseURL:       "https://proxy.example.com",
		UsernameClaim: "preferred_username",
		RoleClaim:     "groups",
		RoleMappings:  map[string]string{"sre": "admin", "helpdesk": "operator"},
		AllowSignup:   true,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	a, err := adminauth.NewOIDCAuthenticator(t.Context(), cfg, db, idp.Client(), discardLogger())
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	return a, idp, db
}

func TestOIDCProvisionsAUserOnFirstSignIn(t *testing.T) {
	t.Parallel()

	a, idp, db := newOIDC(t, nil)
	idp.SetClaims(map[string]any{
		"sub":                "sub-alice",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"name":               "Alice Example",
		"groups":             []any{"sre"},
	})

	user, err := signOn(t, a, idp)
	if err != nil {
		t.Fatalf("sign-on: %v", err)
	}
	if user.Username != "alice" || user.Role != store.RoleAdmin {
		t.Errorf("provisioned %+v, want alice as admin", user)
	}
	if user.Source != store.SourceOIDC || user.Subject.String != "sub-alice" {
		t.Errorf("the identity was not recorded: %+v", user)
	}

	stored, err := db.Users().GetBySubject(t.Context(), store.SourceOIDC, "sub-alice")
	if err != nil {
		t.Fatalf("GetBySubject: %v", err)
	}
	if stored.Email != "alice@example.com" || stored.DisplayName != "Alice Example" {
		t.Errorf("stored user = %+v", stored)
	}
}

// PKCE is verified by the fake the way a real provider does, so a proxy that
// skipped the verifier would fail here rather than silently pass.
func TestOIDCUsesPKCE(t *testing.T) {
	t.Parallel()

	a, idp, _ := newOIDC(t, nil)
	idp.SetClaims(map[string]any{"sub": "sub-alice", "preferred_username": "alice", "groups": []any{"sre"}})

	if _, err := signOn(t, a, idp); err != nil {
		t.Fatalf("sign-on: %v", err)
	}

	requests := idp.TokenRequests()
	if len(requests) != 1 {
		t.Fatalf("the token endpoint saw %d requests, want 1", len(requests))
	}
	if requests[0].Get("code_verifier") == "" {
		t.Error("the code exchange carried no PKCE verifier")
	}
}

func TestOIDCRoleMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		groups  any
		mutate  func(*adminauth.OIDCConfig)
		want    store.Role
		wantErr error
	}{
		{name: "mapped to admin", groups: []any{"sre"}, want: store.RoleAdmin},
		{name: "mapped to operator", groups: []any{"helpdesk"}, want: store.RoleOperator},
		{
			// Being in both groups must give the higher role, not whichever the
			// provider happened to list first.
			name: "the most privileged mapping wins", groups: []any{"helpdesk", "sre"}, want: store.RoleAdmin,
		},
		{
			name: "reverse order gives the same result", groups: []any{"sre", "helpdesk"}, want: store.RoleAdmin,
		},
		{
			// Providers differ on whether a single-valued claim is a string or
			// a one-element array.
			name: "a single string claim", groups: "sre", want: store.RoleAdmin,
		},
		{
			name:   "no match falls back to the default",
			groups: []any{"everyone"},
			mutate: func(c *adminauth.OIDCConfig) { c.DefaultRole = "viewer" },
			want:   store.RoleViewer,
		},
		{
			// With no default, an unmapped user is refused rather than let in
			// with the least privilege — which is what a tenant-wide directory
			// needs.
			name:    "no match and no default is refused",
			groups:  []any{"everyone"},
			wantErr: adminauth.ErrNoRole,
		},
		{
			name:    "no claim at all is refused",
			groups:  nil,
			wantErr: adminauth.ErrNoRole,
		},
		{
			name:   "a mapping to an unknown role is ignored",
			groups: []any{"weird"},
			mutate: func(c *adminauth.OIDCConfig) {
				c.RoleMappings = map[string]string{"weird": "superuser"}
			},
			wantErr: adminauth.ErrNoRole,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, idp, _ := newOIDC(t, tt.mutate)
			claims := map[string]any{"sub": "sub-x", "preferred_username": "x"}
			if tt.groups != nil {
				claims["groups"] = tt.groups
			}
			idp.SetClaims(claims)

			user, err := signOn(t, a, idp)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("sign-on = (%v, %v), want %v", user, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("sign-on: %v", err)
			}
			if user.Role != tt.want {
				t.Errorf("role = %q, want %q", user.Role, tt.want)
			}
		})
	}
}

// Removing someone from a group in the directory has to take effect, and their
// existing sessions must not outlive the demotion.
func TestOIDCReappliesTheRoleOnEverySignIn(t *testing.T) {
	t.Parallel()

	a, idp, db := newOIDC(t, nil)
	idp.SetClaims(map[string]any{"sub": "sub-alice", "preferred_username": "alice", "groups": []any{"sre"}})

	user, err := signOn(t, a, idp)
	if err != nil {
		t.Fatalf("first sign-on: %v", err)
	}
	if user.Role != store.RoleAdmin {
		t.Fatalf("role = %q, want admin", user.Role)
	}

	s := &store.Session{
		UserID:    user.ID,
		TokenHash: store.HashSessionToken("still-admin"),
		CSRFToken: "csrf",
		ExpiresAt: timeHourFromNow(),
	}
	if err := db.Sessions().Create(t.Context(), s); err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	// The directory moves them to the help desk.
	idp.SetClaims(map[string]any{"sub": "sub-alice", "preferred_username": "alice", "groups": []any{"helpdesk"}})
	user, err = signOn(t, a, idp)
	if err != nil {
		t.Fatalf("second sign-on: %v", err)
	}
	if user.Role != store.RoleOperator {
		t.Errorf("role = %q, want operator after the group change", user.Role)
	}
	if _, err := db.Sessions().Lookup(t.Context(), "still-admin", timeHour()); !errors.Is(err, store.ErrNotFound) {
		t.Error("a session survived a demotion, so the old role kept working")
	}
}

func TestOIDCSignupDisabled(t *testing.T) {
	t.Parallel()

	a, idp, _ := newOIDC(t, func(c *adminauth.OIDCConfig) { c.AllowSignup = false })
	idp.SetClaims(map[string]any{"sub": "sub-new", "preferred_username": "newcomer", "groups": []any{"sre"}})

	if _, err := signOn(t, a, idp); !errors.Is(err, adminauth.ErrSignupDisabled) {
		t.Errorf("sign-on = %v, want ErrSignupDisabled", err)
	}
}

func TestOIDCDisabledAccountIsRefused(t *testing.T) {
	t.Parallel()

	a, idp, db := newOIDC(t, nil)
	idp.SetClaims(map[string]any{"sub": "sub-alice", "preferred_username": "alice", "groups": []any{"sre"}})

	user, err := signOn(t, a, idp)
	if err != nil {
		t.Fatalf("sign-on: %v", err)
	}

	user.Disabled = true
	if err := db.Users().Update(t.Context(), user); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// Disabling locally must hold even though the directory still authenticates
	// them.
	if _, err := signOn(t, a, idp); !errors.Is(err, adminauth.ErrInvalidCredentials) {
		t.Errorf("sign-on for a disabled account = %v, want a refusal", err)
	}
}

// The state parameter ties the callback to the request that started it.
func TestOIDCRejectsAMismatchedState(t *testing.T) {
	t.Parallel()

	a, idp, _ := newOIDC(t, nil)
	idp.SetClaims(map[string]any{"sub": "sub-alice", "preferred_username": "alice", "groups": []any{"sre"}})

	req, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	_, err = a.Complete(t.Context(), "any-code", *req, "not-the-state-we-sent", idp.Client())
	if !errors.Is(err, adminauth.ErrBadState) {
		t.Errorf("Complete with a mismatched state = %v, want ErrBadState", err)
	}
	if _, err := a.Complete(t.Context(), "any-code", *req, "", idp.Client()); !errors.Is(err, adminauth.ErrBadState) {
		t.Errorf("Complete with no state = %v, want ErrBadState", err)
	}
}

// The nonce ties the ID token to the request that asked for it, so a token
// obtained elsewhere cannot be replayed here.
func TestOIDCRejectsAMismatchedNonce(t *testing.T) {
	t.Parallel()

	a, idp, _ := newOIDC(t, nil)
	idp.SetClaims(map[string]any{
		"sub": "sub-alice", "preferred_username": "alice", "groups": []any{"sre"},
		// The provider returns a nonce that does not match the request.
		"nonce": "a-different-nonce",
	})

	if _, err := signOn(t, a, idp); !errors.Is(err, adminauth.ErrBadState) {
		t.Errorf("sign-on with a mismatched nonce = %v, want ErrBadState", err)
	}
}

func TestOIDCTokenExchangeFailure(t *testing.T) {
	t.Parallel()

	a, idp, _ := newOIDC(t, nil)
	idp.FailToken(true)

	_, err := signOn(t, a, idp)
	if err == nil {
		t.Fatal("sign-on succeeded despite a failed token exchange")
	}
	if !strings.Contains(err.Error(), "authorization code") {
		t.Errorf("the error does not say what failed: %v", err)
	}
}

func TestOIDCUsernameFallback(t *testing.T) {
	t.Parallel()

	// A provider that populates no preferred_username should still yield a
	// usable account rather than failing.
	a, idp, _ := newOIDC(t, nil)
	idp.SetClaims(map[string]any{
		"sub": "sub-alice", "email": "alice@example.com", "groups": []any{"sre"},
	})

	user, err := signOn(t, a, idp)
	if err != nil {
		t.Fatalf("sign-on: %v", err)
	}
	if user.Username != "alice@example.com" {
		t.Errorf("username = %q, want the email as a fallback", user.Username)
	}
}

func TestOIDCDisabledReturnsNil(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a, err := adminauth.NewOIDCAuthenticator(t.Context(),
		adminauth.OIDCConfig{Enabled: false}, db, nil, discardLogger())
	if err != nil {
		t.Fatalf("NewOIDCAuthenticator: %v", err)
	}
	if a != nil {
		t.Error("a disabled configuration returned an authenticator")
	}
}

func TestOIDCUnreachableIssuer(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	// A misconfigured issuer must fail at startup rather than on first sign-in.
	_, err := adminauth.NewOIDCAuthenticator(t.Context(), adminauth.OIDCConfig{
		Enabled: true, Issuer: "http://127.0.0.1:1", ClientID: "x", BaseURL: "https://proxy.example.com",
	}, db, nil, discardLogger())
	if err == nil {
		t.Error("NewOIDCAuthenticator accepted an unreachable issuer")
	}
}

func TestCallbackPathIsStable(t *testing.T) {
	t.Parallel()

	// It forms the redirect URI registered with the provider, so changing it
	// breaks every existing deployment.
	if adminauth.CallbackPath != "/api/v1/auth/oidc/callback" {
		t.Errorf("CallbackPath = %q; changing it breaks registered redirect URIs", adminauth.CallbackPath)
	}
}

func timeHour() time.Duration    { return time.Hour }
func timeHourFromNow() time.Time { return time.Now().Add(time.Hour) }

func TestOIDCClaimAccessors(t *testing.T) {
	t.Parallel()

	// Providers differ on the shape of the same claim, and on which claims they
	// populate at all. None of that should fail a sign-in.
	tests := []struct {
		name   string
		claims map[string]any
		want   store.Role
	}{
		{
			name:   "groups as a native string slice",
			claims: map[string]any{"sub": "s", "preferred_username": "u", "groups": []any{"sre"}},
			want:   store.RoleAdmin,
		},
		{
			name:   "a numeric claim is not a role",
			claims: map[string]any{"sub": "s", "preferred_username": "u", "groups": 42},
			want:   store.RoleViewer,
		},
		{
			name:   "a mixed array keeps only the strings",
			claims: map[string]any{"sub": "s", "preferred_username": "u", "groups": []any{42, "sre"}},
			want:   store.RoleAdmin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, idp, _ := newOIDC(t, func(c *adminauth.OIDCConfig) { c.DefaultRole = "viewer" })
			idp.SetClaims(tt.claims)

			user, err := signOn(t, a, idp)
			if err != nil {
				t.Fatalf("sign-on: %v", err)
			}
			if user.Role != tt.want {
				t.Errorf("role = %q, want %q", user.Role, tt.want)
			}
		})
	}
}

func TestOIDCUsernameClaimIsConfigurable(t *testing.T) {
	t.Parallel()

	a, idp, _ := newOIDC(t, func(c *adminauth.OIDCConfig) {
		c.UsernameClaim = "upn"
	})
	idp.SetClaims(map[string]any{
		"sub": "sub-alice", "upn": "alice@corp.example", "preferred_username": "ignored",
		"groups": []any{"sre"},
	})

	user, err := signOn(t, a, idp)
	if err != nil {
		t.Fatalf("sign-on: %v", err)
	}
	if user.Username != "alice@corp.example" {
		t.Errorf("username = %q, want the configured claim", user.Username)
	}
}

func TestOIDCStartProducesDistinctRequests(t *testing.T) {
	t.Parallel()

	a, _, _ := newOIDC(t, nil)

	first, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	second, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Reusing state, a nonce or a PKCE verifier across sign-ins would defeat
	// each of them in turn.
	if first.State == second.State || first.Nonce == second.Nonce || first.Verifier == second.Verifier {
		t.Error("two sign-in attempts shared their state, nonce or verifier")
	}
	if !strings.Contains(first.URL, "code_challenge=") {
		t.Errorf("the authorization URL carries no PKCE challenge: %s", first.URL)
	}
	if !strings.Contains(first.URL, "redirect_uri=") {
		t.Errorf("the authorization URL carries no redirect URI: %s", first.URL)
	}
}
