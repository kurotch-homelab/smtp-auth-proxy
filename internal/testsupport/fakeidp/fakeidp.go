// Package fakeidp is a minimal OpenID Connect provider for tests: discovery, a
// JWKS, an authorization endpoint that redirects straight back, and a token
// endpoint that mints a signed ID token.
//
// It exists so the sign-on flow can be exercised end to end — PKCE, state,
// nonce, claim-to-role mapping — without a real identity provider.
package fakeidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Provider is a running fake.
type Provider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	keyID  string

	mu sync.Mutex
	// claims are put into the next ID token.
	claims map[string]any
	// tokenRequests records the form values the token endpoint received.
	tokenRequests []url.Values
	// failToken makes the token endpoint reject the exchange.
	failToken bool
}

// Start brings up a provider and stops it with the test.
func Start(t *testing.T) *Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("fakeidp: generating a key: %v", err)
	}

	p := &Provider{key: key, keyID: "test-key", claims: map[string]any{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

// Issuer is the provider's issuer URL.
func (p *Provider) Issuer() string { return p.server.URL }

// Client returns an HTTP client that can reach the provider.
func (p *Provider) Client() *http.Client { return p.server.Client() }

// SetClaims replaces the claims put into the next ID token.
func (p *Provider) SetClaims(claims map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = claims
}

// FailToken makes the next code exchange fail.
func (p *Provider) FailToken(fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failToken = fail
}

// TokenRequests returns what the token endpoint received.
func (p *Provider) TokenRequests() []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]url.Values(nil), p.tokenRequests...)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                p.server.URL,
		"authorization_endpoint":                p.server.URL + "/authorize",
		"token_endpoint":                        p.server.URL + "/token",
		"jwks_uri":                              p.server.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       p.key.Public(),
		KeyID:     p.keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	writeJSON(w, set)
}

// authorize redirects straight back with a code, standing in for a user who
// signs in and consents.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}

	// The code carries the request's nonce and PKCE challenge so the token
	// endpoint can honor them without server-side state.
	code := encodeCode(pendingCode{
		Nonce:     q.Get("nonce"),
		Challenge: q.Get("code_challenge"),
	})

	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", q.Get("state"))
	redirect.RawQuery = values.Encode()

	// A real provider checks the redirect URI against what was registered. This
	// fake redirects wherever it is told, which is the point: the test drives
	// both ends.
	//nolint:gosec // G710: a deliberate open redirect in a test double
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	p.mu.Lock()
	p.tokenRequests = append(p.tokenRequests, r.Form)
	fail := p.failToken
	claims := p.claims
	p.mu.Unlock()

	if fail {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "invalid_grant"})
		return
	}

	pending, err := decodeCode(r.Form.Get("code"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "invalid_grant", "error_description": err.Error()})
		return
	}

	// Verify PKCE the way a real provider does, so a proxy that skipped the
	// verifier would fail here rather than silently pass.
	if pending.Challenge != "" {
		verifier := r.Form.Get("code_verifier")
		if verifier == "" || s256(verifier) != pending.Challenge {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}

	idToken, err := p.signIDToken(clientID(r), pending.Nonce, claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// clientID reads the client identifier from wherever the client put it.
//
// golang.org/x/oauth2 defaults to client_secret_basic, so it arrives in the
// Authorization header rather than the form; a fake that only looked at the
// form would mint tokens with an empty audience.
func clientID(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok && id != "" {
		return id
	}
	return r.Form.Get("client_id")
}

func (p *Provider) signIDToken(audience, nonce string, extra map[string]any) (string, error) {
	now := time.Now()

	claims := map[string]any{
		"iss": p.server.URL,
		"aud": audience,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"sub": "default-subject",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range extra {
		claims[k] = v
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.keyID),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// pendingCode is what an authorization code carries.
type pendingCode struct {
	Nonce     string `json:"nonce"`
	Challenge string `json:"challenge"`
}

func encodeCode(p pendingCode) string {
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCode(code string) (pendingCode, error) {
	var p pendingCode
	b, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, nil
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
