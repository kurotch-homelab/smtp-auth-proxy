// Package adminauth authenticates and authorizes the management interface:
// local passwords, single sign-on, sessions, CSRF and role checks.
package adminauth

import (
	"fmt"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Permission is one thing a role may or may not do.
//
// Permissions are named after the action rather than the endpoint, so adding a
// route cannot accidentally inherit a broader right than intended.
type Permission string

// The permission set. Keep this list and the table below together: a permission
// with no entry in rolePermissions is denied to everyone, which is the failure
// mode to prefer.
const (
	// PermViewStatus reads the dashboard, queue and delivery history.
	PermViewStatus Permission = "view.status"
	// PermViewConfig reads mailboxes, accounts and settings, with secrets
	// already stripped by the API.
	PermViewConfig Permission = "view.config"
	// PermViewAudit reads the audit log.
	PermViewAudit Permission = "view.audit"

	// PermManageQueue retries, holds and discards queued messages.
	PermManageQueue Permission = "queue.manage"
	// PermReadMessageBody downloads the raw MIME of a queued message, which is
	// the contents of somebody's mail.
	PermReadMessageBody Permission = "queue.read_body"

	// PermManageAccounts creates and edits SMTP accounts.
	PermManageAccounts Permission = "accounts.manage"
	// PermManageMailboxes creates and edits mailboxes.
	PermManageMailboxes Permission = "mailboxes.manage"
	// PermManageCredentials creates and edits OAuth credentials.
	PermManageCredentials Permission = "credentials.manage"
	// PermManageUsers creates and edits administrators.
	PermManageUsers Permission = "users.manage"
	// PermManageSettings changes proxy-wide settings.
	PermManageSettings Permission = "settings.manage"
)

// rolePermissions is the whole authorization model.
//
// viewer reads. operator additionally works the queue. admin additionally
// changes configuration and manages people.
var rolePermissions = map[store.Role]map[Permission]bool{
	store.RoleViewer: {
		PermViewStatus: true,
		PermViewConfig: true,
	},
	store.RoleOperator: {
		PermViewStatus:  true,
		PermViewConfig:  true,
		PermViewAudit:   true,
		PermManageQueue: true,
	},
	store.RoleAdmin: {
		PermViewStatus:        true,
		PermViewConfig:        true,
		PermViewAudit:         true,
		PermManageQueue:       true,
		PermReadMessageBody:   true,
		PermManageAccounts:    true,
		PermManageMailboxes:   true,
		PermManageCredentials: true,
		PermManageUsers:       true,
		PermManageSettings:    true,
	},
}

// AllPermissions lists every permission, for tests that assert the authorization
// matrix is complete.
func AllPermissions() []Permission {
	return []Permission{
		PermViewStatus, PermViewConfig, PermViewAudit,
		PermManageQueue, PermReadMessageBody,
		PermManageAccounts, PermManageMailboxes, PermManageCredentials,
		PermManageUsers, PermManageSettings,
	}
}

// AllRoles lists every role, most privileged first.
func AllRoles() []store.Role {
	return []store.Role{store.RoleAdmin, store.RoleOperator, store.RoleViewer}
}

// Can reports whether a role holds a permission.
//
// An unknown role holds nothing. A binary running against a database written by
// a newer one must not treat a role it does not recognize as privileged.
func Can(role store.Role, perm Permission) bool {
	return rolePermissions[role][perm]
}

// PermissionsFor returns everything a role may do, for the API to hand the UI
// so it can hide what the user cannot use.
func PermissionsFor(role store.Role) []Permission {
	granted := rolePermissions[role]
	out := make([]Permission, 0, len(granted))
	for _, p := range AllPermissions() {
		if granted[p] {
			out = append(out, p)
		}
	}
	return out
}

// ParseRole validates a role name from an API request or a claim mapping.
func ParseRole(s string) (store.Role, error) {
	role := store.Role(s)
	if _, ok := rolePermissions[role]; !ok {
		return "", fmt.Errorf("adminauth: %q is not a valid role (expected admin, operator or viewer)", s)
	}
	return role, nil
}
