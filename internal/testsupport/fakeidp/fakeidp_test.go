package fakeidp_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/fakeidp"
)

func TestDiscoveryDocument(t *testing.T) {
	t.Parallel()

	p := fakeidp.Start(t)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		p.Issuer()+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	resp, err := p.Client().Do(req)
	if err != nil {
		t.Fatalf("fetching the discovery document: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	// go-oidc refuses a document whose issuer does not match the URL it was
	// fetched from, so this has to be exact.
	if doc["issuer"] != p.Issuer() {
		t.Errorf("issuer = %v, want %q", doc["issuer"], p.Issuer())
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if doc[key] == nil {
			t.Errorf("the discovery document has no %s", key)
		}
	}
}

func TestTokenRequestsStartEmpty(t *testing.T) {
	t.Parallel()

	p := fakeidp.Start(t)
	if n := len(p.TokenRequests()); n != 0 {
		t.Errorf("a fresh provider has %d recorded requests", n)
	}
	// The setters must be safe before any request arrives.
	p.SetClaims(map[string]any{"sub": "x"})
	p.FailToken(true)
	p.FailToken(false)
}
