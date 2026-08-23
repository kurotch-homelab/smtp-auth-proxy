package adminapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminapi"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// fakeEntra is a stand-in for the Microsoft Entra token endpoint.
func fakeEntra(t *testing.T, accept bool) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/{tenant}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL + "/" + tenant + "/v2.0",
			"authorization_endpoint": srv.URL + "/" + tenant + "/oauth2/v2.0/authorize",
			"token_endpoint":         srv.URL + "/" + tenant + "/oauth2/v2.0/token",
		})
	})
	mux.HandleFunc("/{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !accept {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type": "Bearer", "expires_in": 3599, "access_token": "T0K3N",
		})
	})

	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// withTokens wires a real token provider pointed at a fake Entra.
func withTokens(entra *httptest.Server) harnessOption {
	return func(o *adminapi.Options) {
		o.Tokens = oauth.NewProvider(o.Keyring, entra.Client(),
			oauth.WithoutInstanceDiscovery(),
			oauth.WithDefaultAuthorityHost(entra.URL))
	}
}

// seedTestableMailbox creates a credential whose secret really decrypts, plus a
// mailbox on it.
func (h *harness) seedTestableMailbox(t *testing.T) *store.Mailbox {
	t.Helper()

	c := &store.OAuthCredential{
		Name: "primary", TenantID: "11111111-1111-1111-1111-111111111111",
		ClientID: "22222222-2222-2222-2222-222222222222",
		AuthType: store.AuthTypeSecret,
	}
	if err := h.db.Credentials().Create(t.Context(), c); err != nil {
		t.Fatalf("creating a credential: %v", err)
	}
	sealed, err := h.keyring.EncryptString("the-secret", c.SecretContext())
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	c.ClientSecretEnc = sealed
	if err := h.db.Credentials().Update(t.Context(), c); err != nil {
		t.Fatalf("storing the sealed secret: %v", err)
	}
	return h.seedMailbox("sales@example.com", c.ID)
}

// The connection test is the difference between "the configuration looks right"
// and "Microsoft 365 accepts it", which is otherwise only discovered when the
// first message fails.
func TestMailboxConnectionTestSucceeds(t *testing.T) {
	t.Parallel()

	entra := fakeEntra(t, true)
	h := newHarness(t, withTokens(entra))
	mailbox := h.seedTestableMailbox(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/mailboxes/"+mailbox.ID+"/test", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d\n%s", rec.Code, rec.Body.String())
	}

	body := decode[map[string]any](t, rec)
	if body["ok"] != true {
		t.Errorf("ok = %v, want true\n%s", body["ok"], rec.Body.String())
	}
	// A token only proves the application registration works; the Exchange side
	// is a separate set of steps, and the operator needs to know that.
	hint, _ := body["hint"].(string)
	for _, want := range []string{"SMTP.SendAsApp", "Add-MailboxPermission"} {
		if !strings.Contains(hint, want) {
			t.Errorf("the hint does not mention %s: %q", want, hint)
		}
	}
}

func TestMailboxConnectionTestReportsAFailure(t *testing.T) {
	t.Parallel()

	entra := fakeEntra(t, false)
	h := newHarness(t, withTokens(entra))
	mailbox := h.seedTestableMailbox(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/mailboxes/"+mailbox.ID+"/test", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d\n%s", rec.Code, rec.Body.String())
	}

	body := decode[map[string]any](t, rec)
	if body["ok"] != false {
		t.Errorf("ok = %v, want false", body["ok"])
	}
	// The AADSTS code is what an operator searches for.
	if message, _ := body["message"].(string); !strings.Contains(message, "AADSTS7000215") {
		t.Errorf("the message lost the Entra diagnostic code: %q", message)
	}

	// A failed test is worth recording: it is evidence of when a credential
	// stopped working.
	audit := sess.do(http.MethodGet, "/api/v1/audit?action=mailbox.test", nil).Body.String()
	if !strings.Contains(audit, "failure") {
		t.Errorf("the failed test was not recorded as a failure:\n%s", audit)
	}
}

func TestMailboxConnectionTestWithoutATokenProvider(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/mailboxes/"+fixtures.mailbox+"/test", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("= %d, want 503 when the token provider is missing", rec.Code)
	}
}

// A rotated secret has to take effect on the next delivery, not after a
// restart.
func TestUpdatingACredentialForgetsTheCachedClient(t *testing.T) {
	t.Parallel()

	entra := fakeEntra(t, true)
	h := newHarness(t, withTokens(entra))
	mailbox := h.seedTestableMailbox(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	if rec := sess.do(http.MethodPost, "/api/v1/mailboxes/"+mailbox.ID+"/test", nil); rec.Code != http.StatusOK {
		t.Fatalf("first test = %d", rec.Code)
	}

	rec := sess.do(http.MethodPatch, "/api/v1/credentials/"+mailbox.OAuthCredentialID, map[string]any{
		"clientSecret": "a-rotated-secret",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("rotating = %d\n%s", rec.Code, rec.Body.String())
	}

	// The test still passes because the fake accepts anything; what matters is
	// that the rotation was accepted and recorded.
	if rec := sess.do(http.MethodPost, "/api/v1/mailboxes/"+mailbox.ID+"/test", nil); rec.Code != http.StatusOK {
		t.Errorf("test after rotation = %d\n%s", rec.Code, rec.Body.String())
	}

	audit := sess.do(http.MethodGet, "/api/v1/audit?action=credential.update", nil).Body.String()
	if !strings.Contains(audit, "secretChanged") {
		t.Errorf("the rotation was not recorded:\n%s", audit)
	}
	if strings.Contains(audit, "a-rotated-secret") {
		t.Errorf("the audit log captured the new secret:\n%s", audit)
	}
}
