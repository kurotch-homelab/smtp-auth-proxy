package adminapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

func TestLoginAndSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.user("alice", store.RoleAdmin)

	rec := h.anonymous(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "alice", "password": adminPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d\n%s", rec.Code, rec.Body.String())
	}

	body := decode[map[string]any](t, rec)
	if body["csrfToken"] == "" || body["csrfToken"] == nil {
		t.Error("login returned no CSRF token")
	}
	// The UI hides what the user cannot do, so it needs the list.
	perms, ok := body["permissions"].([]any)
	if !ok || len(perms) == 0 {
		t.Errorf("login returned no permissions: %v", body["permissions"])
	}

	// The session cookie must be set, HttpOnly, and must not be the CSRF token.
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login set no cookie")
	}
	session := cookies[0]
	if !session.HttpOnly {
		t.Error("the session cookie is not HttpOnly")
	}
	if session.Value == body["csrfToken"] {
		t.Error("the session cookie and the CSRF token are the same value")
	}
}

func TestLoginRejections(t *testing.T) {
	// Not parallel: the subtests share a harness and collect their messages to
	// compare afterwards.

	h := newHarness(t)
	h.user("alice", store.RoleAdmin)

	tests := []struct {
		name     string
		body     map[string]string
		wantCode int
	}{
		{name: "wrong password", body: map[string]string{"username": "alice", "password": "nope"}, wantCode: http.StatusUnauthorized},
		{name: "unknown user", body: map[string]string{"username": "nobody", "password": "nope"}, wantCode: http.StatusUnauthorized},
		{name: "missing password", body: map[string]string{"username": "alice"}, wantCode: http.StatusUnprocessableEntity},
		{name: "missing username", body: map[string]string{"password": "x"}, wantCode: http.StatusUnprocessableEntity},
	}

	var messages []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := h.anonymous(http.MethodPost, "/api/v1/auth/login", tt.body)
			if rec.Code != tt.wantCode {
				t.Errorf("= %d, want %d\n%s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if rec.Code == http.StatusUnauthorized {
				messages = append(messages, apiError(t, rec).Message)
			}
		})
	}

	// A wrong password and an unknown user must be indistinguishable, or the
	// sign-in page enumerates who administers the proxy.
	if len(messages) == 2 && messages[0] != messages[1] {
		t.Errorf("the responses differ:\n  %q\n  %q", messages[0], messages[1])
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	if rec := sess.do(http.MethodPost, "/api/v1/auth/logout", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d\n%s", rec.Code, rec.Body.String())
	}
	if rec := sess.do(http.MethodGet, "/api/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the session survived sign-out: %d", rec.Code)
	}
}

// Secrets must never come back out, in any form — not the plaintext, and not
// the sealed ciphertext either.
func TestCredentialSecretsNeverLeave(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "primary", "tenantId": "tenant-id", "clientId": "client-id",
		"authType": "secret", "clientSecret": "the-actual-secret",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}
	created := decode[map[string]any](t, rec)
	id, _ := created["id"].(string)

	for _, body := range []string{
		rec.Body.String(),
		sess.do(http.MethodGet, "/api/v1/credentials", nil).Body.String(),
		sess.do(http.MethodGet, "/api/v1/credentials/"+id, nil).Body.String(),
	} {
		if strings.Contains(body, "the-actual-secret") {
			t.Errorf("the client secret was returned:\n%s", body)
		}
		// The sealed form is no better: it is still the secret, and the
		// encryption key is one configuration mistake away.
		if strings.Contains(body, "v1.k1.") {
			t.Errorf("the sealed secret was returned:\n%s", body)
		}
	}

	// The UI still needs to know one is configured.
	if created["hasSecret"] != true {
		t.Errorf("hasSecret = %v, want true", created["hasSecret"])
	}
}

func TestCredentialSetupNamesTheThreeTenantSteps(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodGet, "/api/v1/credentials/"+fixtures.credential+"/setup", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup = %d\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// The three things that have to be true before Exchange accepts a token,
	// none of which can be discovered from the error it returns.
	for _, want := range []string{"SMTP.SendAsApp", "New-ServicePrincipal", "Add-MailboxPermission"} {
		if !strings.Contains(body, want) {
			t.Errorf("the setup instructions do not mention %s:\n%s", want, body)
		}
	}
	// The single most common mistake.
	if !strings.Contains(body, "Enterprise applications") {
		t.Error("the instructions do not warn which Object ID to use")
	}
	// The commands should carry the credential's own values.
	if !strings.Contains(body, "sales@example.com") {
		t.Error("the commands do not name the mailbox this credential sends as")
	}
}

func TestAccountPasswordIsReturnedOnceAndGenerated(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/accounts", map[string]any{
		"username": "svc-nas", "defaultMailboxId": fixtures.mailbox,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}

	created := decode[map[string]any](t, rec)
	password, _ := created["password"].(string)
	if password == "" {
		t.Fatal("no password was generated for the new account")
	}
	id, _ := created["id"].(string)

	// It must never appear again — there is no way to display it a second time,
	// and an API that could would be storing it recoverably.
	later := sess.do(http.MethodGet, "/api/v1/accounts/"+id, nil).Body.String()
	if strings.Contains(later, password) {
		t.Errorf("the password was returned again:\n%s", later)
	}
	if strings.Contains(later, "passwordHash") || strings.Contains(later, "argon2") {
		t.Errorf("the password hash was returned:\n%s", later)
	}
}

func TestAccountValidation(t *testing.T) {
	// Not parallel: the subtests share one harness and its fixtures.

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	tests := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{name: "no username", body: map[string]any{}, field: "username"},
		{
			name:  "invalid sender pattern",
			body:  map[string]any{"username": "svc", "allowedSenders": []string{"*"}},
			field: "allowedSenders",
		},
		{
			name:  "invalid CIDR",
			body:  map[string]any{"username": "svc", "allowCidrs": []string{"10.0.0.1"}},
			field: "allowCidrs",
		},
		{
			name:  "unknown sender policy",
			body:  map[string]any{"username": "svc", "fromPolicy": "allow-everything"},
			field: "fromPolicy",
		},
		{
			// Exchange Online will not honor a higher budget; it answers
			// "4.7.500 Server busy" instead.
			name:  "rate above the Exchange limit",
			body:  map[string]any{"username": "svc", "rateLimitPerMin": 500},
			field: "rateLimitPerMin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := sess.do(http.MethodPost, "/api/v1/accounts", tt.body)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("= %d, want 422\n%s", rec.Code, rec.Body.String())
			}
			if _, ok := apiError(t, rec).Fields[tt.field]; !ok {
				t.Errorf("no message for %q: %s", tt.field, rec.Body.String())
			}
		})
	}
	_ = fixtures
}

func TestMailboxValidation(t *testing.T) {
	// Not parallel: the subtests share one harness and its fixtures.

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	tests := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{
			name:  "not an address",
			body:  map[string]any{"address": "not-an-address", "oauthCredentialId": fixtures.credential, "transport": "smtp"},
			field: "address",
		},
		{
			name:  "unknown transport",
			body:  map[string]any{"address": "a@example.com", "oauthCredentialId": fixtures.credential, "transport": "carrier-pigeon"},
			field: "transport",
		},
		{
			name: "concurrency above the Exchange limit",
			body: map[string]any{
				"address": "a@example.com", "oauthCredentialId": fixtures.credential,
				"transport": "smtp", "maxConcurrent": 10,
			},
			field: "maxConcurrent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := sess.do(http.MethodPost, "/api/v1/mailboxes", tt.body)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("= %d, want 422\n%s", rec.Code, rec.Body.String())
			}
			if _, ok := apiError(t, rec).Fields[tt.field]; !ok {
				t.Errorf("no message for %q: %s", tt.field, rec.Body.String())
			}
		})
	}
}

// Removing the last administrator would lock everyone out of their own proxy,
// with no way back short of editing the database.
func TestCannotRemoveTheLastAdministrator(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	alice := h.user("alice", store.RoleAdmin)
	bob := h.user("bob", store.RoleAdmin)
	sess := h.signIn(alice)

	// Demoting one of two is fine.
	if rec := sess.do(http.MethodPatch, "/api/v1/users/"+bob.ID,
		map[string]any{"role": "viewer"}); rec.Code != http.StatusOK {
		t.Fatalf("demoting the second admin = %d\n%s", rec.Code, rec.Body.String())
	}

	// Demoting the last one is not.
	rec := sess.do(http.MethodPatch, "/api/v1/users/"+alice.ID, map[string]any{"role": "viewer"})
	if rec.Code != http.StatusConflict {
		t.Errorf("demoting the last admin = %d, want 409\n%s", rec.Code, rec.Body.String())
	}
	rec = sess.do(http.MethodPatch, "/api/v1/users/"+alice.ID, map[string]any{"disabled": true})
	if rec.Code != http.StatusConflict {
		t.Errorf("disabling the last admin = %d, want 409\n%s", rec.Code, rec.Body.String())
	}
}

func TestCannotDeleteYourOwnAccount(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	alice := h.user("alice", store.RoleAdmin)
	h.user("bob", store.RoleAdmin)
	sess := h.signIn(alice)

	// There is no undo, and it is almost always a mistake.
	rec := sess.do(http.MethodDelete, "/api/v1/users/"+alice.ID, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("deleting your own account = %d, want 409\n%s", rec.Code, rec.Body.String())
	}
}

// A demotion has to take effect now, not whenever the user next signs out.
func TestDemotionRevokesSessions(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	alice := h.user("alice", store.RoleAdmin)
	bob := h.user("bob", store.RoleAdmin)

	adminSess := h.signIn(alice)
	bobSess := h.signIn(bob)

	if rec := bobSess.do(http.MethodGet, "/api/v1/users", nil); rec.Code != http.StatusOK {
		t.Fatalf("bob could not list users while an admin: %d", rec.Code)
	}

	if rec := adminSess.do(http.MethodPatch, "/api/v1/users/"+bob.ID,
		map[string]any{"role": "viewer"}); rec.Code != http.StatusOK {
		t.Fatalf("demoting bob = %d\n%s", rec.Code, rec.Body.String())
	}

	if rec := bobSess.do(http.MethodGet, "/api/v1/users", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("bob's session survived the demotion: %d", rec.Code)
	}
}

func TestQueueActions(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleOperator))

	if rec := sess.do(http.MethodPost, "/api/v1/messages/"+fixtures.message+"/hold", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("hold = %d\n%s", rec.Code, rec.Body.String())
	}
	got := decode[map[string]any](t, sess.do(http.MethodGet, "/api/v1/messages/"+fixtures.message, nil))
	if got["status"] != string(store.StatusHeld) {
		t.Errorf("status = %v, want held", got["status"])
	}

	if rec := sess.do(http.MethodPost, "/api/v1/messages/"+fixtures.message+"/retry", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("retry = %d\n%s", rec.Code, rec.Body.String())
	}
	got = decode[map[string]any](t, sess.do(http.MethodGet, "/api/v1/messages/"+fixtures.message, nil))
	if got["status"] != string(store.StatusQueued) {
		t.Errorf("status = %v, want queued", got["status"])
	}
}

// A message listing must not carry the message itself; downloading it is a
// separate endpoint behind a separate permission.
func TestMessageListingOmitsTheBody(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleViewer))

	body := sess.do(http.MethodGet, "/api/v1/messages", nil).Body.String()
	if strings.Contains(body, "Subject: test") || strings.Contains(body, "\\r\\n\\r\\nbody") {
		t.Errorf("the listing carried the message content:\n%s", body)
	}
	_ = fixtures
}

func TestMessageBodyDownload(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodGet, "/api/v1/messages/"+fixtures.message+"/body", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("body = %d\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Subject: test") {
		t.Errorf("the body did not come back:\n%s", rec.Body.String())
	}
	// Served as a download, not as a page a browser would render.
	if got := rec.Header().Get("Content-Type"); got != "message/rfc822" {
		t.Errorf("Content-Type = %q", got)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", rec.Header().Get("Content-Disposition"))
	}

	// Reading somebody's mail is worth an audit entry.
	audit := sess.do(http.MethodGet, "/api/v1/audit?action=message.read_body", nil).Body.String()
	if !strings.Contains(audit, "message.read_body") {
		t.Errorf("no audit entry for reading a message body:\n%s", audit)
	}
}

func TestAuditRecordsChangesWithoutSecrets(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "primary", "tenantId": "t", "clientId": "c",
		"authType": "secret", "clientSecret": "super-secret-value",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}

	audit := sess.do(http.MethodGet, "/api/v1/audit", nil).Body.String()
	if !strings.Contains(audit, "credential.create") {
		t.Errorf("the change was not recorded:\n%s", audit)
	}
	if !strings.Contains(audit, "alice") {
		t.Errorf("the audit entry does not name who did it:\n%s", audit)
	}
	// The audit log records what changed, not the values.
	if strings.Contains(audit, "super-secret-value") {
		t.Errorf("the audit log captured the secret:\n%s", audit)
	}
}

func TestUnknownEndpointReturnsJSON(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	rec := h.anonymous(http.MethodGet, "/api/v1/nope", nil)

	if rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404", rec.Code)
	}
	// The UI parses every response as JSON; an HTML 404 would break it.
	if got := apiError(t, rec).Code; got != "not_found" {
		t.Errorf("code = %q, want not_found", got)
	}
}

func TestUnknownFieldsAreRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	// A client sending "enable" instead of "enabled" should hear about it
	// rather than silently changing nothing.
	rec := sess.do(http.MethodPatch, "/api/v1/mailboxes/"+fixtures.mailbox,
		map[string]any{"enable": false})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("= %d, want 400 for an unknown field\n%s", rec.Code, rec.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	rec := h.anonymous(http.MethodGet, "/healthz", nil)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the CSP does not forbid framing: %q", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("the CSP is not restricted to this origin: %q", csp)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	if rec := h.anonymous(http.MethodGet, "/healthz", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}
	// Readiness checks the database, because a proxy that cannot reach its
	// queue cannot accept mail either.
	if rec := h.anonymous(http.MethodGet, "/readyz", nil); rec.Code != http.StatusOK {
		t.Errorf("readyz = %d\n%s", rec.Code, rec.Body.String())
	}

	if err := h.db.Close(); err != nil {
		t.Fatalf("closing the database: %v", err)
	}
	if rec := h.anonymous(http.MethodGet, "/readyz", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz with the database down = %d, want 503", rec.Code)
	}
}

func TestStatusDashboard(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleViewer))

	rec := sess.do(http.MethodGet, "/api/v1/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d\n%s", rec.Code, rec.Body.String())
	}

	body := decode[map[string]any](t, rec)
	for _, key := range []string{"version", "queueByStatus", "mailboxes", "accounts", "credentials"} {
		if _, ok := body[key]; !ok {
			t.Errorf("the dashboard has no %q:\n%s", key, rec.Body.String())
		}
	}
}
