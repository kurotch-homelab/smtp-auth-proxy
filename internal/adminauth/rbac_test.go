package adminauth

import (
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// The whole authorization model, written out so a change to the table is a
// change to this test too. Anything not listed is denied.
func TestPermissionMatrix(t *testing.T) {
	t.Parallel()

	expected := map[store.Role][]Permission{
		store.RoleViewer: {PermViewStatus, PermViewConfig},
		store.RoleOperator: {
			PermViewStatus, PermViewConfig, PermViewAudit, PermManageQueue,
		},
		store.RoleAdmin: AllPermissions(),
	}

	for _, role := range AllRoles() {
		granted := map[Permission]bool{}
		for _, p := range expected[role] {
			granted[p] = true
		}

		for _, perm := range AllPermissions() {
			want := granted[perm]
			if got := Can(role, perm); got != want {
				t.Errorf("Can(%q, %q) = %v, want %v", role, perm, got, want)
			}
		}
	}
}

// A role the database holds but this binary does not know — an older replica
// against a newer schema — must be treated as holding nothing, not as trusted.
func TestUnknownRoleHoldsNothing(t *testing.T) {
	t.Parallel()

	for _, perm := range AllPermissions() {
		if Can(store.Role("superuser"), perm) {
			t.Errorf("an unknown role was granted %q", perm)
		}
		if Can("", perm) {
			t.Errorf("the empty role was granted %q", perm)
		}
	}
}

// Reading a queued message means reading somebody's mail, so it is deliberately
// narrower than working the queue.
func TestOnlyAdminsCanReadMessageBodies(t *testing.T) {
	t.Parallel()

	if !Can(store.RoleAdmin, PermReadMessageBody) {
		t.Error("an admin cannot read a message body")
	}
	for _, role := range []store.Role{store.RoleOperator, store.RoleViewer} {
		if Can(role, PermReadMessageBody) {
			t.Errorf("%q can read message bodies", role)
		}
	}
	// An operator still has to be able to work the queue without reading it.
	if !Can(store.RoleOperator, PermManageQueue) {
		t.Error("an operator cannot manage the queue")
	}
}

func TestViewerChangesNothing(t *testing.T) {
	t.Parallel()

	mutating := []Permission{
		PermManageQueue, PermManageAccounts, PermManageMailboxes,
		PermManageCredentials, PermManageUsers, PermManageSettings,
	}
	for _, perm := range mutating {
		if Can(store.RoleViewer, perm) {
			t.Errorf("a viewer holds the mutating permission %q", perm)
		}
	}
}

func TestPermissionsFor(t *testing.T) {
	t.Parallel()

	admin := PermissionsFor(store.RoleAdmin)
	if len(admin) != len(AllPermissions()) {
		t.Errorf("an admin holds %d permissions, want all %d", len(admin), len(AllPermissions()))
	}
	if got := PermissionsFor(store.Role("nope")); len(got) != 0 {
		t.Errorf("an unknown role holds %v", got)
	}
}

func TestParseRole(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{"admin", "operator", "viewer"} {
		if _, err := ParseRole(valid); err != nil {
			t.Errorf("ParseRole(%q) = %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "Admin", "superuser", "root"} {
		if _, err := ParseRole(invalid); err == nil {
			t.Errorf("ParseRole(%q) was accepted", invalid)
		}
	}
}
