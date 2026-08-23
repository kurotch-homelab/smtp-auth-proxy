package adminapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

func TestMailboxLifecycle(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	credential := h.seedCredential("primary")
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/mailboxes", map[string]any{
		"address": "Sales@Example.com", "displayName": "Sales",
		"oauthCredentialId": credential.ID, "transport": "smtp",
		"rateLimitPerMin": 20, "maxConcurrent": 2,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}
	created := decode[map[string]any](t, rec)
	id, _ := created["id"].(string)

	// The address is normalized, so a mailbox entered with different casing is
	// the same mailbox as far as the sender policy is concerned.
	if created["address"] != "sales@example.com" {
		t.Errorf("address = %v, want it lowercased", created["address"])
	}
	if created["credentialName"] != "primary" {
		t.Errorf("credentialName = %v, want the credential resolved for display", created["credentialName"])
	}

	rec = sess.do(http.MethodPatch, "/api/v1/mailboxes/"+id, map[string]any{
		"transport": "graph", "enabled": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d\n%s", rec.Code, rec.Body.String())
	}
	updated := decode[map[string]any](t, rec)
	if updated["transport"] != "graph" || updated["enabled"] != false {
		t.Errorf("update did not persist: %v", updated)
	}
	// An untouched field must survive a partial update.
	if updated["displayName"] != "Sales" {
		t.Errorf("displayName = %v, want it left alone", updated["displayName"])
	}

	if rec := sess.do(http.MethodDelete, "/api/v1/mailboxes/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d\n%s", rec.Code, rec.Body.String())
	}
	if rec := sess.do(http.MethodGet, "/api/v1/mailboxes/"+id, nil); rec.Code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", rec.Code)
	}
}

func TestAccountLifecycle(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	credential := h.seedCredential("primary")
	sales := h.seedMailbox("sales@example.com", credential.ID)
	support := h.seedMailbox("support@example.com", credential.ID)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/accounts", map[string]any{
		"username": "svc-printer", "description": "the office MFP",
		"defaultMailboxId": sales.ID,
		"mailboxIds":       []string{sales.ID, support.ID},
		"allowedSenders":   []string{"noreply@example.com", "*@example.org"},
		"fromPolicy":       "rewrite",
		"allowCidrs":       []string{"10.0.0.0/8"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}
	created := decode[map[string]any](t, rec)
	id, _ := created["id"].(string)

	got := decode[map[string]any](t, sess.do(http.MethodGet, "/api/v1/accounts/"+id, nil))
	if addresses, _ := got["mailboxAddresses"].([]any); len(addresses) != 2 {
		t.Errorf("mailboxAddresses = %v, want both mailboxes", got["mailboxAddresses"])
	}
	if senders, _ := got["allowedSenders"].([]any); len(senders) != 2 {
		t.Errorf("allowedSenders = %v, want both patterns", got["allowedSenders"])
	}
	if got["fromPolicy"] != "rewrite" {
		t.Errorf("fromPolicy = %v", got["fromPolicy"])
	}

	// Replacing the mailbox list must remove the ones left out, or revoking
	// access in the UI would not revoke anything.
	rec = sess.do(http.MethodPatch, "/api/v1/accounts/"+id, map[string]any{
		"mailboxIds": []string{sales.ID}, "enabled": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d\n%s", rec.Code, rec.Body.String())
	}
	updated := decode[map[string]any](t, rec)
	if addresses, _ := updated["mailboxAddresses"].([]any); len(addresses) != 1 {
		t.Errorf("mailboxAddresses = %v, want only the one that was kept", updated["mailboxAddresses"])
	}
	if updated["enabled"] != false {
		t.Errorf("enabled = %v, want false", updated["enabled"])
	}

	// Resetting the password returns a new one, once.
	rec = sess.do(http.MethodPost, "/api/v1/accounts/"+id+"/password", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("password reset = %d\n%s", rec.Code, rec.Body.String())
	}
	if decode[map[string]string](t, rec)["password"] == "" {
		t.Error("the reset returned no password")
	}

	if rec := sess.do(http.MethodDelete, "/api/v1/accounts/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestCredentialLifecycle(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "primary", "tenantId": "tenant-id", "clientId": "client-id",
		"authType": "secret", "clientSecret": "s1",
		"authorityHost": "https://login.microsoftonline.us",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}
	id, _ := decode[map[string]any](t, rec)["id"].(string)

	// Rotating the secret is a normal update, and the UI can send back an
	// object it never received the secret for.
	rec = sess.do(http.MethodPatch, "/api/v1/credentials/"+id, map[string]any{
		"name": "primary-renamed",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update without a secret = %d\n%s", rec.Code, rec.Body.String())
	}
	updated := decode[map[string]any](t, rec)
	if updated["name"] != "primary-renamed" {
		t.Errorf("name = %v", updated["name"])
	}
	// Omitting the secret must leave the stored one alone, not clear it.
	if updated["hasSecret"] != true {
		t.Error("an update that did not mention the secret cleared it")
	}

	if rec := sess.do(http.MethodDelete, "/api/v1/credentials/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d\n%s", rec.Code, rec.Body.String())
	}
}

// Deleting a credential a mailbox still uses would leave that mailbox unable to
// authenticate, which shows up as mail silently failing.
func TestCredentialInUseCannotBeDeleted(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodDelete, "/api/v1/credentials/"+fixtures.credential, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("= %d, want 409\n%s", rec.Code, rec.Body.String())
	}
	if got := apiError(t, rec).Code; got != "still_referenced" {
		t.Errorf("code = %q, want still_referenced", got)
	}
}

func TestDuplicateNamesConflict(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.seedCredential("primary")
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/credentials", map[string]any{
		"name": "primary", "tenantId": "t", "clientId": "c",
		"authType": "secret", "clientSecret": "s",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("= %d, want 409\n%s", rec.Code, rec.Body.String())
	}
	if got := apiError(t, rec).Code; got != "conflict" {
		t.Errorf("code = %q, want conflict", got)
	}
}

// Objects declared in a bootstrap file are the file's to change, not the UI's.
func TestBootstrapManagedObjectsAreReadOnly(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	credential := h.seedCredential("primary")
	mailbox := h.seedMailbox("sales@example.com", credential.ID)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	mailbox.ManagedBy = store.ManagedByBootstrap
	if err := h.db.Mailboxes().Update(t.Context(), mailbox); err != nil {
		t.Fatalf("Update: %v", err)
	}

	for _, attempt := range []struct {
		method string
		body   any
	}{
		{http.MethodPatch, map[string]any{"enabled": false}},
		{http.MethodDelete, nil},
	} {
		rec := sess.do(attempt.method, "/api/v1/mailboxes/"+mailbox.ID, attempt.body)
		if rec.Code != http.StatusConflict {
			t.Errorf("%s = %d, want 409\n%s", attempt.method, rec.Code, rec.Body.String())
			continue
		}
		if got := apiError(t, rec).Code; got != "managed_externally" {
			t.Errorf("%s code = %q, want managed_externally", attempt.method, got)
		}
		if !strings.Contains(apiError(t, rec).Message, "bootstrap") {
			t.Errorf("%s message does not say where to change it: %q", attempt.method, apiError(t, rec).Message)
		}
	}
}

func TestChangeOwnPassword(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	user := h.user("alice", store.RoleViewer)
	sess := h.signIn(user)

	// The current password is re-checked: a session left open on a shared
	// machine should not be enough to lock its owner out.
	rec := sess.do(http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": "wrong", "newPassword": "a-long-enough-password",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("with a wrong current password = %d, want 401", rec.Code)
	}

	// Too short.
	rec = sess.do(http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": adminPassword, "newPassword": "short",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("with a short password = %d, want 422", rec.Code)
	}

	rec = sess.do(http.MethodPost, "/api/v1/auth/password", map[string]any{
		"currentPassword": adminPassword, "newPassword": "a-long-enough-password",
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change = %d\n%s", rec.Code, rec.Body.String())
	}
	// Changing a password ends every session, this one included.
	if rec := sess.do(http.MethodGet, "/api/v1/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("the session survived a password change: %d", rec.Code)
	}
}

func TestUserLifecycle(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	rec := sess.do(http.MethodPost, "/api/v1/users", map[string]any{
		"username": "bob", "email": "bob@example.com",
		"role": "operator", "password": "a-long-enough-password",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d\n%s", rec.Code, rec.Body.String())
	}
	created := decode[map[string]any](t, rec)
	id, _ := created["id"].(string)

	// A hash is not something a client should ever see.
	if strings.Contains(rec.Body.String(), "argon2") || strings.Contains(rec.Body.String(), "a-long-enough-password") {
		t.Errorf("the response carried password material:\n%s", rec.Body.String())
	}
	if created["hasPassword"] != true {
		t.Error("hasPassword = false for an account with a password")
	}

	// Too short.
	rec = sess.do(http.MethodPost, "/api/v1/users", map[string]any{
		"username": "carol", "role": "viewer", "password": "short",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("a short password = %d, want 422", rec.Code)
	}
	// Unknown role.
	rec = sess.do(http.MethodPost, "/api/v1/users", map[string]any{
		"username": "carol", "role": "superuser", "password": "a-long-enough-password",
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("an unknown role = %d, want 422", rec.Code)
	}

	if rec := sess.do(http.MethodPost, "/api/v1/users/"+id+"/password",
		map[string]any{"password": "another-long-password"}); rec.Code != http.StatusNoContent {
		t.Fatalf("setting a password = %d\n%s", rec.Code, rec.Body.String())
	}

	if rec := sess.do(http.MethodDelete, "/api/v1/users/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestNotFoundForUnknownIdentifiers(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	sess := h.signIn(h.user("alice", store.RoleAdmin))

	paths := []string{
		"/api/v1/credentials/nope",
		"/api/v1/mailboxes/nope",
		"/api/v1/accounts/nope",
		"/api/v1/messages/nope",
		"/api/v1/users/nope",
	}
	for _, path := range paths {
		rec := sess.do(http.MethodGet, path, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}
