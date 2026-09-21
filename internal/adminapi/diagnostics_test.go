package adminapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/legal"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func TestDiagnosticSendAndReplay(t *testing.T) {
	h := newHarness(t)
	mb := h.seedTestableMailbox(t)
	sess := h.signIn(h.user("operator", store.RoleOperator))
	path := "/api/v1/mailboxes/" + mb.ID
	info := sess.do(http.MethodGet, path+"/diagnostics", nil)
	if info.Code != http.StatusOK || strings.Contains(info.Body.String(), "the-secret") {
		t.Fatalf("diagnostics: %d %s", info.Code, info.Body.String())
	}
	req := map[string]string{"requestId": store.NewID(), "recipient": "to@example.net"}
	first := sess.do(http.MethodPost, path+"/test-send", req)
	if first.Code != http.StatusAccepted {
		t.Fatalf("send: %d %s", first.Code, first.Body.String())
	}
	id, ok := decode[map[string]any](t, first)["messageId"].(string)
	if !ok {
		t.Fatal("missing message ID")
	}
	replay := sess.do(http.MethodPost, path+"/test-send", req)
	if replay.Code != http.StatusAccepted || decode[map[string]any](t, replay)["messageId"] != id {
		t.Fatalf("replay: %s", replay.Body.String())
	}
	req["recipient"] = "other@example.net"
	if got := sess.do(http.MethodPost, path+"/test-send", req); got.Code != http.StatusConflict {
		t.Fatalf("changed payload: %d", got.Code)
	}
	for _, recipient := range []string{"", "<>", "a@example.net,b@example.net", "a@example.net\r\nBcc: b@example.net"} {
		req["requestId"], req["recipient"] = store.NewID(), recipient
		if got := sess.do(http.MethodPost, path+"/test-send", req); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("invalid recipient %q: %d", recipient, got.Code)
		}
	}
	mb.Enabled = false
	if err := h.db.Mailboxes().Update(t.Context(), mb); err != nil {
		t.Fatal(err)
	}
	req["requestId"], req["recipient"] = store.NewID(), "to@example.net"
	if got := sess.do(http.MethodPost, path+"/test-send", req); got.Code != http.StatusConflict {
		t.Fatalf("disabled: %d %s", got.Code, got.Body.String())
	}
	mb.Enabled = true
	if err := h.db.Mailboxes().Update(t.Context(), mb); err != nil {
		t.Fatal(err)
	}
	credential, err := h.db.Credentials().Get(t.Context(), mb.OAuthCredentialID)
	if err != nil {
		t.Fatal(err)
	}
	credential.ClientSecretEnc = ""
	if err := h.db.Credentials().Update(t.Context(), credential); err != nil {
		t.Fatal(err)
	}
	req["requestId"] = store.NewID()
	if got := sess.do(http.MethodPost, path+"/test-send", req); got.Code != http.StatusConflict {
		t.Fatalf("missing credential material: %d", got.Code)
	}

	m, err := h.db.Messages().Get(t.Context(), id)
	if err != nil || m.Origin != "diagnostic" || m.SMTPAccountID.Valid {
		t.Fatalf("message: %+v %v", m, err)
	}
	if got := sess.do(http.MethodGet, "/api/v1/messages/"+id+"/body", nil); got.Code != http.StatusForbidden {
		t.Fatal("operator can read mail body")
	}
	audit := sess.do(http.MethodGet, "/api/v1/audit?action=mailbox.test_send", nil)
	if !strings.Contains(audit.Body.String(), "operator") || strings.Contains(audit.Body.String(), "the-secret") {
		t.Fatalf("audit: %s", audit.Body.String())
	}
	if decode[struct{ Total int }](t, audit).Total != 1 {
		t.Fatal("replay duplicated the audit entry")
	}
	if err := h.db.Mailboxes().Delete(t.Context(), mb.ID); err != nil {
		t.Fatal(err)
	}
	historical := sess.do(http.MethodGet, "/api/v1/messages/"+id, nil)
	record := decode[map[string]any](t, historical)
	if record["mailboxId"] != nil || record["mailboxAddress"] != mb.Address {
		t.Fatalf("deleted relation not preserved correctly: %s", historical.Body.String())
	}
}

func TestPublicLicenseBytesMatchBinary(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/licenses", "/licenses?download=1"} {
		response := h.signIn(h.user(store.NewID(), store.RoleViewer)).do(http.MethodGet, path, nil)
		if response.Code != http.StatusOK || response.Body.String() != legal.Notices {
			t.Fatal("notice contents differ")
		}
	}
}

func TestAPIMessageOperationStates(t *testing.T) {
	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			h := newHarnessForDriver(t, driver)
			sess := h.signIn(h.user("operator", store.RoleOperator))
			for _, status := range []store.MessageStatus{store.StatusQueued, store.StatusSending, store.StatusFailed, store.StatusDeferred, store.StatusHeld, store.StatusSent} {
				for _, action := range []string{"retry", "hold", "delete"} {
					m := &store.Message{Status: status, EnvelopeFrom: "a@example.com", Recipients: []string{"b@example.com"}}
					if err := h.db.Messages().Enqueue(t.Context(), m, []byte("body")); err != nil {
						t.Fatal(err)
					}
					method, path := http.MethodPost, "/api/v1/messages/"+m.ID+"/"+action
					allowed := false
					switch action {
					case "retry":
						allowed = status == store.StatusFailed || status == store.StatusDeferred || status == store.StatusHeld
					case "hold":
						allowed = status == store.StatusQueued || status == store.StatusFailed || status == store.StatusDeferred
					case "delete":
						method, path = http.MethodDelete, "/api/v1/messages/"+m.ID
						allowed = status != store.StatusSending
					}
					result := sess.do(method, path, nil)
					if (allowed && result.Code != http.StatusNoContent) || (!allowed && result.Code != http.StatusConflict) {
						t.Errorf("%s %s: %d %s", status, action, result.Code, result.Body.String())
					}
				}
			}
		})
	}
}
