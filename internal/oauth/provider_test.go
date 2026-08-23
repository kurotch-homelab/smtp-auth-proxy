package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

// fakeEntra serves just enough of Microsoft Entra for MSAL to complete a client
// credentials request: instance discovery, OpenID metadata, and the token
// endpoint itself.
type fakeEntra struct {
	server *httptest.Server

	mu sync.Mutex
	// requests records the form values posted to the token endpoint, so a test
	// can assert on the grant type and scope that were actually sent.
	requests []map[string]string
	// token is handed out on success.
	token string
	// status and body, when set, replace the success response.
	status int
	body   string
}

func startFakeEntra(t *testing.T) *fakeEntra {
	t.Helper()

	f := &fakeEntra{token: "T0K3N", status: http.StatusOK}

	mux := http.NewServeMux()
	mux.HandleFunc("/common/discovery/instance", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"tenant_discovery_endpoint": f.server.URL + "/" + testTenant + "/v2.0/.well-known/openid-configuration",
			"metadata":                  []any{},
		})
	})
	mux.HandleFunc("/{tenant}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		writeJSON(w, map[string]any{
			"issuer":                 f.server.URL + "/" + tenant + "/v2.0",
			"authorization_endpoint": f.server.URL + "/" + tenant + "/oauth2/v2.0/authorize",
			"token_endpoint":         f.server.URL + "/" + tenant + "/oauth2/v2.0/token",
		})
	})
	mux.HandleFunc("/{tenant}/oauth2/v2.0/token", f.handleToken)

	// MSAL refuses a non-https authority, so the fake has to serve TLS; its own
	// client trusts the generated certificate.
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeEntra) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	form := make(map[string]string, len(r.Form))
	for k := range r.Form {
		form[k] = r.Form.Get(k)
	}

	f.mu.Lock()
	f.requests = append(f.requests, form)
	status, body, token := f.status, f.body, f.token
	f.mu.Unlock()

	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return
	}

	writeJSON(w, map[string]any{
		"token_type":     "Bearer",
		"expires_in":     3599,
		"ext_expires_in": 3599,
		"access_token":   token,
	})
}

func (f *fakeEntra) reject(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeEntra) tokenRequests() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.requests...)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// keyring returns a throwaway keyring.
func keyring(t *testing.T) *appcrypto.Keyring {
	t.Helper()

	spec, err := appcrypto.GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := appcrypto.NewKeyring(spec)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

// secretCredential builds a credential whose secret is sealed with kr.
func secretCredential(t *testing.T, kr *appcrypto.Keyring, authority string) *store.OAuthCredential {
	t.Helper()

	cred := &store.OAuthCredential{
		ID:            "cred-1",
		Name:          "primary",
		TenantID:      testTenant,
		ClientID:      "22222222-2222-2222-2222-222222222222",
		AuthType:      store.AuthTypeSecret,
		AuthorityHost: authority,
	}
	sealed, err := kr.EncryptString("the-client-secret", cred.SecretContext())
	if err != nil {
		t.Fatalf("sealing the secret: %v", err)
	}
	cred.ClientSecretEnc = sealed
	return cred
}

const exchangeScope = "https://outlook.office365.com/.default"

func TestProviderAcquiresAToken(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())
	token, err := p.Token(t.Context(), cred, exchangeScope)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token.AccessToken != "T0K3N" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}
	if !token.Usable(time.Now()) {
		t.Errorf("a freshly issued token is not usable: expires %v", token.ExpiresAt)
	}

	requests := entra.tokenRequests()
	if len(requests) != 1 {
		t.Fatalf("the token endpoint saw %d requests, want 1", len(requests))
	}
	// Exchange Online's SMTP AUTH needs the client credentials grant with the
	// Outlook scope; anything else silently yields a token that will not work.
	if got := requests[0]["grant_type"]; got != "client_credentials" {
		t.Errorf("grant_type = %q, want client_credentials", got)
	}
	// MSAL appends the reserved OIDC scopes to whatever it is given; Entra
	// ignores them alongside a `.default` scope. What matters is that the
	// Exchange Online scope is present as its own entry — anything else yields
	// a token that authenticates but cannot submit mail.
	if !slices.Contains(strings.Fields(requests[0]["scope"]), exchangeScope) {
		t.Errorf("scope = %q, want it to include %q", requests[0]["scope"], exchangeScope)
	}
	if got := requests[0]["client_secret"]; got != "the-client-secret" {
		t.Errorf("client_secret was not the decrypted value: %q", got)
	}
}

func TestProviderCachesTokens(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())
	for range 5 {
		if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}

	// At 30 messages a minute, fetching a fresh token per message would be a
	// request to Entra for every message sent.
	if n := len(entra.tokenRequests()); n != 1 {
		t.Errorf("the token endpoint saw %d requests, want 1 after caching", n)
	}
}

func TestProviderRefetchesAfterACredentialChanges(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())
	if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token: %v", err)
	}

	// Rotating the secret in the admin interface must take effect without a
	// restart.
	rotated, err := kr.EncryptString("a-new-secret", cred.SecretContext())
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	cred.ClientSecretEnc = rotated

	if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token after rotation: %v", err)
	}

	requests := entra.tokenRequests()
	if len(requests) != 2 {
		t.Fatalf("the token endpoint saw %d requests, want 2 after a rotation", len(requests))
	}
	if got := requests[1]["client_secret"]; got != "a-new-secret" {
		t.Errorf("the second request used %q, want the rotated secret", got)
	}
}

func TestProviderForget(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())
	if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token: %v", err)
	}

	p.Forget(cred.ID)
	if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token after Forget: %v", err)
	}
	if n := len(entra.tokenRequests()); n != 2 {
		t.Errorf("the token endpoint saw %d requests, want 2 after Forget", n)
	}
}

func TestProviderReportsAnUndecryptableSecret(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)
	// A secret sealed under a key that is no longer configured, which is what a
	// botched key rotation leaves behind.
	cred.ClientSecretEnc = "v1.gone.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())
	_, err := p.Token(t.Context(), cred, exchangeScope)
	if !errors.Is(err, oauth.ErrCredentialUnusable) {
		t.Errorf("Token = %v, want ErrCredentialUnusable", err)
	}
	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("the error does not name the credential: %v", err)
	}
}

func TestProviderReportsAnUnknownAuthType(t *testing.T) {
	t.Parallel()

	kr := keyring(t)
	cred := &store.OAuthCredential{
		ID: "c", Name: "odd", TenantID: testTenant, ClientID: "client",
		AuthType: store.AuthType("magic"),
	}

	p := oauth.NewProvider(kr, nil)
	if _, err := p.Token(t.Context(), cred, exchangeScope); !errors.Is(err, oauth.ErrCredentialUnusable) {
		t.Errorf("Token = %v, want ErrCredentialUnusable", err)
	}
}

func TestProviderReportsARejectedRequest(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)
	entra.reject(http.StatusUnauthorized,
		`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`)

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())
	_, err := p.Token(t.Context(), cred, exchangeScope)
	if !errors.Is(err, oauth.ErrTokenRequestFailed) {
		t.Fatalf("Token = %v, want ErrTokenRequestFailed", err)
	}
	// The AADSTS code is what an operator searches for.
	if !strings.Contains(err.Error(), "AADSTS7000215") {
		t.Errorf("the error lost the Entra diagnostic code: %v", err)
	}
}

func TestProviderRequiresAScope(t *testing.T) {
	t.Parallel()

	p := oauth.NewProvider(keyring(t), nil)
	if _, err := p.Token(t.Context(), &store.OAuthCredential{}, ""); err == nil {
		t.Error("Token accepted an empty scope")
	}
}

func TestProviderIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, entra.server.URL)

	p := oauth.NewProvider(kr, entra.server.Client(), oauth.WithoutInstanceDiscovery())

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Token(context.Background(), cred, exchangeScope); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Token: %v", err)
	}
}

func TestAuthorityURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		host    string
		tenant  string
		want    string
		wantErr bool
	}{
		{
			name: "default host", host: "", tenant: testTenant,
			want: oauth.DefaultAuthorityHost + "/" + testTenant,
		},
		{
			name: "explicit host", host: "https://login.microsoftonline.us", tenant: testTenant,
			want: "https://login.microsoftonline.us/" + testTenant,
		},
		{
			name: "trailing slash is trimmed", host: "https://login.microsoftonline.com/", tenant: testTenant,
			want: "https://login.microsoftonline.com/" + testTenant,
		},
		{name: "no tenant", host: "", tenant: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := oauth.AuthorityURL(tt.host, tt.tenant)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("AuthorityURL = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuthorityURL: %v", err)
			}
			if got != tt.want {
				t.Errorf("AuthorityURL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenUsable(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name string
		tok  oauth.Token
		want bool
	}{
		{name: "fresh", tok: oauth.Token{AccessToken: "t", ExpiresAt: now.Add(time.Hour)}, want: true},
		{name: "expired", tok: oauth.Token{AccessToken: "t", ExpiresAt: now.Add(-time.Minute)}},
		// A token about to expire must not start a delivery that could outlive
		// it.
		{name: "inside the refresh margin", tok: oauth.Token{AccessToken: "t", ExpiresAt: now.Add(time.Minute)}},
		{name: "just outside the margin", tok: oauth.Token{AccessToken: "t", ExpiresAt: now.Add(oauth.RefreshMargin + time.Minute)}, want: true},
		{name: "empty", tok: oauth.Token{ExpiresAt: now.Add(time.Hour)}},
	}

	for _, tt := range tests {
		if got := tt.tok.Usable(now); got != tt.want {
			t.Errorf("%s: Usable = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func ExampleBuildXOAuth2() {
	sasl, _ := oauth.BuildXOAuth2("shared@example.com", "T0K3N")
	// The separators are literal 0x01 bytes, shown here as \x01.
	fmt.Printf("%q\n", sasl)
	// Output:
	// "user=shared@example.com\x01auth=Bearer T0K3N\x01\x01"
}

// The configured authority must apply to credentials that do not name one.
// Without this the provider silently used the worldwide commercial cloud
// whatever the deployment configured, which is wrong for a sovereign cloud and
// invisible until mail stops.
func TestProviderUsesTheConfiguredDefaultAuthority(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)

	// No AuthorityHost on the credential itself.
	cred := secretCredential(t, kr, "")

	p := oauth.NewProvider(kr, entra.server.Client(),
		oauth.WithoutInstanceDiscovery(),
		oauth.WithDefaultAuthorityHost(entra.server.URL))

	if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if n := len(entra.tokenRequests()); n != 1 {
		t.Errorf("the configured authority saw %d requests, want 1", n)
	}
}

func TestCredentialAuthorityOverridesTheDefault(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)

	// A credential that names its own authority wins over the default, which is
	// how one deployment can serve tenants in different clouds.
	cred := secretCredential(t, kr, entra.server.URL)

	p := oauth.NewProvider(kr, entra.server.Client(),
		oauth.WithoutInstanceDiscovery(),
		oauth.WithDefaultAuthorityHost("https://login.microsoftonline.us"))

	if _, err := p.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if n := len(entra.tokenRequests()); n != 1 {
		t.Errorf("the credential's own authority saw %d requests, want 1", n)
	}
}

func TestChangingTheDefaultAuthorityRebuildsTheClient(t *testing.T) {
	t.Parallel()

	entra := startFakeEntra(t)
	kr := keyring(t)
	cred := secretCredential(t, kr, "")

	// Two providers with different defaults must not share a cached client for
	// the same credential.
	wrong := oauth.NewProvider(kr, entra.server.Client(),
		oauth.WithoutInstanceDiscovery(),
		oauth.WithDefaultAuthorityHost("https://127.0.0.1:1"))
	if _, err := wrong.Token(t.Context(), cred, exchangeScope); err == nil {
		t.Fatal("a token was issued by an unreachable authority")
	}

	right := oauth.NewProvider(kr, entra.server.Client(),
		oauth.WithoutInstanceDiscovery(),
		oauth.WithDefaultAuthorityHost(entra.server.URL))
	if _, err := right.Token(t.Context(), cred, exchangeScope); err != nil {
		t.Fatalf("Token: %v", err)
	}
}
