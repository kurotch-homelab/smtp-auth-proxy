package adminapi_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// endpoint is one route and who may call it.
type endpoint struct {
	Method string
	// Path is the concrete path used in the request, with {id} substituted.
	Path string
	// Allowed lists the roles that must succeed. Every other role must get 403.
	Allowed []store.Role
	// Anonymous means the route is reachable with no session at all.
	Anonymous bool
	// Body is sent for methods that take one.
	Body any
}

var (
	admin    = store.RoleAdmin
	operator = store.RoleOperator
	viewer   = store.RoleViewer
)

// authorizationMatrix is the whole API, and who may call each part of it.
//
// TestEveryRouteHasAnAuthorizationExpectation walks the router and fails on any
// route missing from this table, so a new endpoint cannot be added without
// someone deciding who may reach it.
func authorizationMatrix() []endpoint {
	return []endpoint{
		// Unauthenticated: a probe has no credentials, and the sign-in page has
		// to be reachable before there is a session.
		{Method: "GET", Path: "/healthz", Anonymous: true},
		{Method: "GET", Path: "/readyz", Anonymous: true},
		{Method: "GET", Path: "/api/v1/auth/config", Anonymous: true},
		{Method: "POST", Path: "/api/v1/auth/login", Anonymous: true, Body: map[string]string{"username": "x", "password": "y"}},
		{Method: "GET", Path: "/api/v1/auth/oidc/start", Anonymous: true},
		{Method: "GET", Path: "/api/v1/auth/oidc/callback", Anonymous: true},

		// Signed in, but no particular permission.
		{Method: "POST", Path: "/api/v1/auth/logout", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/auth/me", Allowed: []store.Role{admin, operator, viewer}},
		{
			Method: "POST", Path: "/api/v1/auth/password",
			Allowed: []store.Role{admin, operator, viewer},
			Body:    map[string]string{"currentPassword": adminPassword, "newPassword": "a-long-enough-password"},
		},

		{Method: "GET", Path: "/api/v1/status", Allowed: []store.Role{admin, operator, viewer}},

		// Configuration is readable by everyone signed in; the API strips
		// secrets before it leaves.
		{Method: "GET", Path: "/api/v1/credentials", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/credentials/{credential}", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/credentials/{credential}/setup", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/mailboxes", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/mailboxes/{mailbox}", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/accounts", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/accounts/{account}", Allowed: []store.Role{admin, operator, viewer}},

		// Changing configuration is administrators only.
		{Method: "POST", Path: "/api/v1/credentials", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "PATCH", Path: "/api/v1/credentials/{credential}", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "DELETE", Path: "/api/v1/credentials/{credential}", Allowed: []store.Role{admin}},
		{Method: "POST", Path: "/api/v1/mailboxes", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "PATCH", Path: "/api/v1/mailboxes/{mailbox}", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "DELETE", Path: "/api/v1/mailboxes/{mailbox}", Allowed: []store.Role{admin}},
		{Method: "POST", Path: "/api/v1/mailboxes/{mailbox}/test", Allowed: []store.Role{admin}},
		{Method: "POST", Path: "/api/v1/accounts", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "PATCH", Path: "/api/v1/accounts/{account}", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "DELETE", Path: "/api/v1/accounts/{account}", Allowed: []store.Role{admin}},
		{Method: "POST", Path: "/api/v1/accounts/{account}/password", Allowed: []store.Role{admin}, Body: map[string]any{}},

		// The queue: readable by everyone, workable by operators and above.
		{Method: "GET", Path: "/api/v1/messages", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "GET", Path: "/api/v1/messages/{message}", Allowed: []store.Role{admin, operator, viewer}},
		{Method: "POST", Path: "/api/v1/messages/{message}/retry", Allowed: []store.Role{admin, operator}},
		{Method: "POST", Path: "/api/v1/messages/{message}/hold", Allowed: []store.Role{admin, operator}},
		{Method: "DELETE", Path: "/api/v1/messages/{message}", Allowed: []store.Role{admin, operator}},

		// Reading a message body means reading somebody's mail. Narrower than
		// working the queue on purpose.
		{Method: "GET", Path: "/api/v1/messages/{message}/body", Allowed: []store.Role{admin}},

		// The audit log names who did what, so a viewer does not get it.
		{Method: "GET", Path: "/api/v1/audit", Allowed: []store.Role{admin, operator}},

		// User administration.
		{Method: "GET", Path: "/api/v1/users", Allowed: []store.Role{admin}},
		{Method: "POST", Path: "/api/v1/users", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "GET", Path: "/api/v1/users/{user}", Allowed: []store.Role{admin}},
		{Method: "PATCH", Path: "/api/v1/users/{user}", Allowed: []store.Role{admin}, Body: map[string]any{}},
		{Method: "DELETE", Path: "/api/v1/users/{user}", Allowed: []store.Role{admin}},
		{Method: "POST", Path: "/api/v1/users/{user}/password", Allowed: []store.Role{admin}, Body: map[string]any{}},
	}
}

// TestAuthorizationMatrix drives every endpoint as every role.
//
// A role that is not listed as allowed must get 403 — never a 200, and never a
// 404 that hides whether the object exists.
func TestAuthorizationMatrix(t *testing.T) {
	t.Parallel()

	for _, ep := range authorizationMatrix() {
		if ep.Anonymous {
			// No role gate to test; TestAnonymousRoutesAreReachable covers these.
			continue
		}

		t.Run(ep.Method+" "+ep.Path, func(t *testing.T) {
			t.Parallel()

			for _, role := range []store.Role{admin, operator, viewer} {
				h := newHarness(t)
				fixtures := h.seedAll()
				path := fixtures.resolve(ep.Path)

				// Every test database needs a second administrator, or deleting
				// or demoting one hits the last-admin guard instead of the
				// authorization check under test.
				h.user("spare-admin", store.RoleAdmin)
				actor := h.user("actor-"+string(role), role)
				sess := h.signIn(actor)

				rec := sess.do(ep.Method, path, ep.Body)
				allowed := containsRole(ep.Allowed, role)

				if !allowed {
					if rec.Code != http.StatusForbidden {
						t.Errorf("%s as %s = %d, want 403\n%s", path, role, rec.Code, rec.Body.String())
					}
					continue
				}
				if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
					t.Errorf("%s as %s = %d, want it to be permitted\n%s",
						path, role, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

// The routes that must work before anyone is signed in: the probes, the
// sign-in page's configuration, and sign-in itself. A 401 from bad credentials
// is fine here; a 401 from the session check is not, because it would make the
// sign-in page unreachable.
func TestAnonymousRoutesAreReachable(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()

	for _, ep := range authorizationMatrix() {
		if !ep.Anonymous {
			continue
		}

		rec := h.anonymous(ep.Method, fixtures.resolve(ep.Path), ep.Body)
		if rec.Code == http.StatusForbidden {
			t.Errorf("%s %s with no session = 403; it has to be reachable before sign-in\n%s",
				ep.Method, ep.Path, rec.Body.String())
			continue
		}
		if strings.Contains(rec.Body.String(), "sign in to continue") {
			t.Errorf("%s %s was refused by the session check:\n%s",
				ep.Method, ep.Path, rec.Body.String())
		}
	}
}

// Anything that is not explicitly anonymous must refuse a request with no
// session, rather than falling through to a handler.
func TestEverythingElseRequiresASession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()

	for _, ep := range authorizationMatrix() {
		if ep.Anonymous {
			continue
		}
		rec := h.anonymous(ep.Method, fixtures.resolve(ep.Path), ep.Body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no session = %d, want 401\n%s",
				ep.Method, ep.Path, rec.Code, rec.Body.String())
		}
	}
}

// A state-changing request without the CSRF token must be refused, whatever the
// role: the session cookie is sent automatically, so the token is what proves
// the request came from the admin interface.
func TestMutatingRoutesRequireCSRF(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	fixtures := h.seedAll()
	actor := h.user("alice", store.RoleAdmin)
	sess := h.signIn(actor)

	for _, ep := range authorizationMatrix() {
		if ep.Anonymous || ep.Method == http.MethodGet {
			continue
		}

		// Same session, no CSRF header.
		rec := h.request(ep.Method, fixtures.resolve(ep.Path), ep.Body, sess.token, "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s without a CSRF token = %d, want 403\n%s",
				ep.Method, ep.Path, rec.Code, rec.Body.String())
			continue
		}
		if got := apiError(t, rec).Code; got != "csrf_failed" {
			t.Errorf("%s %s = code %q, want csrf_failed", ep.Method, ep.Path, got)
		}
	}
}

// TestEveryRouteHasAnAuthorizationExpectation walks the router itself.
//
// This is what makes the matrix above trustworthy: adding an endpoint without
// adding a row here fails the build rather than shipping an unreviewed one.
func TestEveryRouteHasAnAuthorizationExpectation(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	declared := map[string]bool{}
	for _, ep := range authorizationMatrix() {
		declared[ep.Method+" "+normalizePattern(ep.Path)] = true
	}

	router, ok := h.server.Handler().(chi.Routes)
	if !ok {
		t.Fatalf("the handler is %T, which cannot be walked", h.server.Handler())
	}

	var missing []string
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := method + " " + normalizePattern(route)
		if !declared[key] {
			missing = append(missing, key)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}

	if len(missing) > 0 {
		t.Errorf("these routes have no entry in authorizationMatrix():\n  %s\n\n"+
			"Add one deciding which roles may call it.", strings.Join(missing, "\n  "))
	}
}

// normalizePattern reduces a route to a comparable shape: chi reports "/{id}"
// while the matrix names its fixtures, and trailing slashes differ.
func normalizePattern(route string) string {
	route = strings.TrimSuffix(route, "/")
	if route == "" {
		route = "/"
	}

	parts := strings.Split(route, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func containsRole(roles []store.Role, role store.Role) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// fixtures are the objects the matrix paths refer to.
type fixtures struct {
	credential string
	mailbox    string
	account    string
	message    string
	user       string
}

func (h *harness) seedAll() fixtures {
	h.t.Helper()

	credential := h.seedCredential("primary")
	mailbox := h.seedMailbox("sales@example.com", credential.ID)
	account := h.seedAccount("svc-printer", mailbox.ID)
	message := h.seedMessage(mailbox)
	target := h.user("target-user", store.RoleViewer)

	return fixtures{
		credential: credential.ID, mailbox: mailbox.ID,
		account: account.ID, message: message.ID, user: target.ID,
	}
}

// resolve substitutes fixture identifiers into a matrix path.
func (f fixtures) resolve(path string) string {
	replacer := strings.NewReplacer(
		"{credential}", f.credential,
		"{mailbox}", f.mailbox,
		"{account}", f.account,
		"{message}", f.message,
		"{user}", f.user,
	)
	return replacer.Replace(path)
}

var _ = fmt.Sprintf
