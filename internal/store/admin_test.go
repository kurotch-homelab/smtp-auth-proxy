package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func newUser(t *testing.T, db *store.DB, username string, role store.Role) *store.AdminUser {
	t.Helper()

	u := &store.AdminUser{
		Username:     username,
		Email:        username + "@example.com",
		PasswordHash: store.NullString("$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg"),
		Role:         role,
		Source:       store.SourceLocal,
	}
	if err := db.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("creating user %q: %v", username, err)
	}
	return u
}

func TestUserCRUD(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			u := newUser(t, db, "alice", store.RoleAdmin)

			byName, err := db.Users().GetByUsername(t.Context(), "alice")
			if err != nil || byName.ID != u.ID {
				t.Fatalf("GetByUsername = (%v, %v)", byName, err)
			}
			if byName.Source != store.SourceLocal {
				t.Errorf("Source = %q, want local", byName.Source)
			}

			u.Role = store.RoleOperator
			u.DisplayName = "Alice"
			if err := db.Users().Update(t.Context(), u); err != nil {
				t.Fatalf("Update: %v", err)
			}
			reread, err := db.Users().Get(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if reread.Role != store.RoleOperator || reread.DisplayName != "Alice" {
				t.Errorf("Update did not persist: %+v", reread)
			}

			if err := db.Users().Delete(t.Context(), u.ID); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := db.Users().Get(t.Context(), u.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get after Delete = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestUserUniqueUsername(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	newUser(t, db, "alice", store.RoleAdmin)

	dup := &store.AdminUser{Username: "alice", Role: store.RoleViewer, Source: store.SourceLocal}
	if err := db.Users().Create(t.Context(), dup); !errors.Is(err, store.ErrConflict) {
		t.Errorf("Create with a duplicate username = %v, want ErrConflict", err)
	}
}

func TestUserBySubject(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	u := &store.AdminUser{
		Username: "bob", Role: store.RoleViewer,
		Source: store.SourceOIDC, Subject: store.NullString("sub-123"),
	}
	if err := db.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := db.Users().GetBySubject(t.Context(), store.SourceOIDC, "sub-123")
	if err != nil || got.ID != u.ID {
		t.Fatalf("GetBySubject = (%v, %v)", got, err)
	}
	if _, err := db.Users().GetBySubject(t.Context(), store.SourceOIDC, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetBySubject for an unknown subject = %v, want ErrNotFound", err)
	}

	// Two local users may both have a NULL subject; the uniqueness constraint
	// must only apply where one is set.
	newUser(t, db, "carol", store.RoleViewer)
	newUser(t, db, "dave", store.RoleViewer)
}

func TestUserCountByRole(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	newUser(t, db, "alice", store.RoleAdmin)
	newUser(t, db, "bob", store.RoleAdmin)
	newUser(t, db, "carol", store.RoleViewer)

	disabled := newUser(t, db, "dave", store.RoleAdmin)
	disabled.Disabled = true
	if err := db.Users().Update(t.Context(), disabled); err != nil {
		t.Fatalf("Update: %v", err)
	}

	counts, err := db.Users().CountByRole(t.Context())
	if err != nil {
		t.Fatalf("CountByRole: %v", err)
	}
	// A disabled administrator cannot sign in, so it must not count towards
	// "there is still someone who can administer this".
	if counts[store.RoleAdmin] != 2 {
		t.Errorf("admins = %d, want 2 (a disabled one must not count)", counts[store.RoleAdmin])
	}
	if counts[store.RoleViewer] != 1 {
		t.Errorf("viewers = %d, want 1", counts[store.RoleViewer])
	}
}

func TestUserLockout(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	u := newUser(t, db, "alice", store.RoleAdmin)

	for range 2 {
		if err := db.Users().RecordFailedLogin(t.Context(), u.ID, 3, time.Minute); err != nil {
			t.Fatalf("RecordFailedLogin: %v", err)
		}
	}
	got, err := db.Users().Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedLogins != 2 {
		t.Errorf("FailedLogins = %d, want 2", got.FailedLogins)
	}
	if got.LockedAt(time.Now()) {
		t.Error("the account locked before reaching the threshold")
	}

	if err := db.Users().RecordFailedLogin(t.Context(), u.ID, 3, time.Minute); err != nil {
		t.Fatalf("RecordFailedLogin: %v", err)
	}
	got, err = db.Users().Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LockedAt(time.Now()) {
		t.Error("the account did not lock at the threshold")
	}
	if got.CanSignIn(time.Now()) {
		t.Error("CanSignIn is true for a locked account")
	}
	// The lock has to lift on its own; an operator locked out by a typo should
	// not need a database edit.
	if got.LockedAt(time.Now().Add(2 * time.Minute)) {
		t.Error("the lock did not expire")
	}

	if err := db.Users().RecordSuccessfulLogin(t.Context(), u.ID); err != nil {
		t.Fatalf("RecordSuccessfulLogin: %v", err)
	}
	got, err = db.Users().Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedLogins != 0 || got.LockedUntil.Valid {
		t.Errorf("a successful login did not clear the lockout: %+v", got)
	}
	if !got.LastLoginAt.Valid {
		t.Error("LastLoginAt was not stamped")
	}
}

func newSession(t *testing.T, db *store.DB, userID, token string, expires time.Time) *store.Session {
	t.Helper()

	s := &store.Session{
		UserID:    userID,
		TokenHash: store.HashSessionToken(token),
		CSRFToken: "csrf-" + token,
		IP:        "10.0.0.5",
		UserAgent: "test",
		ExpiresAt: expires,
	}
	if err := db.Sessions().Create(t.Context(), s); err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	return s
}

func TestSessionLookup(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			u := newUser(t, db, "alice", store.RoleAdmin)
			newSession(t, db, u.ID, "the-token", time.Now().Add(time.Hour))

			got, err := db.Sessions().Lookup(t.Context(), "the-token", time.Hour)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if got.User.ID != u.ID || got.User.Role != store.RoleAdmin {
				t.Errorf("Lookup returned %+v", got.User)
			}
			if got.Session.CSRFToken != "csrf-the-token" {
				t.Errorf("CSRFToken = %q", got.Session.CSRFToken)
			}

			// The raw token must never be stored.
			var stored string
			err = db.QueryRowContext(t.Context(),
				db.Rebind(`SELECT token_hash FROM admin_sessions WHERE id = ?`), got.Session.ID).Scan(&stored)
			if err != nil {
				t.Fatalf("reading the stored token: %v", err)
			}
			if strings.Contains(stored, "the-token") {
				t.Error("the session token was stored in the clear")
			}
		})
	}
}

func TestSessionLookupRejections(t *testing.T) {
	// Not parallel: the subtests share one user and the last one disables it.
	db := storetest.Open(t, store.DriverSQLite)
	u := newUser(t, db, "alice", store.RoleAdmin)

	t.Run("unknown token", func(t *testing.T) {
		if _, err := db.Sessions().Lookup(t.Context(), "nope", time.Hour); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Lookup = %v, want ErrNotFound", err)
		}
	})

	t.Run("expired session", func(t *testing.T) {
		newSession(t, db, u.ID, "expired", time.Now().Add(-time.Minute))
		if _, err := db.Sessions().Lookup(t.Context(), "expired", time.Hour); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Lookup = %v, want ErrNotFound", err)
		}
		// An expired session is cleaned up as it is found, so an abandoned
		// browser does not leave rows behind until the next sweep.
		var n int
		if err := db.QueryRowContext(t.Context(),
			db.Rebind(`SELECT COUNT(*) FROM admin_sessions WHERE token_hash = ?`),
			store.HashSessionToken("expired")).Scan(&n); err != nil {
			t.Fatalf("counting: %v", err)
		}
		if n != 0 {
			t.Error("the expired session was left in the database")
		}
	})

	t.Run("idle too long", func(t *testing.T) {
		newSession(t, db, u.ID, "idle", time.Now().Add(time.Hour))
		// A zero idle window means every session looks idle.
		if _, err := db.Sessions().Lookup(t.Context(), "idle", time.Nanosecond); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Lookup = %v, want ErrNotFound", err)
		}
	})

	t.Run("disabled user", func(t *testing.T) {
		newSession(t, db, u.ID, "disabled-user", time.Now().Add(time.Hour))
		u.Disabled = true
		if err := db.Users().Update(t.Context(), u); err != nil {
			t.Fatalf("Update: %v", err)
		}
		// Disabling an account must take effect immediately, not whenever the
		// user next signs out.
		if _, err := db.Sessions().Lookup(t.Context(), "disabled-user", time.Hour); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Lookup = %v, want ErrNotFound", err)
		}
	})
}

func TestSessionTouchAndDelete(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	u := newUser(t, db, "alice", store.RoleAdmin)
	s := newSession(t, db, u.ID, "the-token", time.Now().Add(time.Hour))

	if err := db.Sessions().Touch(t.Context(), s.ID); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if err := db.Sessions().Delete(t.Context(), s.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := db.Sessions().Lookup(t.Context(), "the-token", time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Lookup after Delete = %v, want ErrNotFound", err)
	}
}

// Changing a password or a role has to end every existing session, or a demoted
// user keeps their old privileges until they happen to sign out.
func TestSessionDeleteForUser(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	alice := newUser(t, db, "alice", store.RoleAdmin)
	bob := newUser(t, db, "bob", store.RoleViewer)

	newSession(t, db, alice.ID, "alice-1", time.Now().Add(time.Hour))
	newSession(t, db, alice.ID, "alice-2", time.Now().Add(time.Hour))
	newSession(t, db, bob.ID, "bob-1", time.Now().Add(time.Hour))

	n, err := db.Sessions().DeleteForUser(t.Context(), alice.ID)
	if err != nil {
		t.Fatalf("DeleteForUser: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d sessions, want 2", n)
	}
	if _, err := db.Sessions().Lookup(t.Context(), "bob-1", time.Hour); err != nil {
		t.Errorf("another user's session was deleted: %v", err)
	}
}

func TestSessionsGoWithTheUser(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	u := newUser(t, db, "alice", store.RoleAdmin)
	newSession(t, db, u.ID, "the-token", time.Now().Add(time.Hour))

	if err := db.Users().Delete(t.Context(), u.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := db.Sessions().Lookup(t.Context(), "the-token", time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a session outlived its user: %v", err)
	}
}

func TestSessionListAndPurge(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	u := newUser(t, db, "alice", store.RoleAdmin)
	newSession(t, db, u.ID, "live", time.Now().Add(time.Hour))
	newSession(t, db, u.ID, "dead", time.Now().Add(-time.Hour))

	live, err := db.Sessions().ListForUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(live) != 1 {
		t.Errorf("ListForUser returned %d sessions, want only the live one", len(live))
	}

	n, err := db.Sessions().PurgeExpired(t.Context())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n != 1 {
		t.Errorf("purged %d sessions, want 1", n)
	}
}

// SQLite stores a time.Time as text including its offset, so a value written in
// local time compares wrong against one in UTC. Every write path normalizes;
// this checks the comparison that matters most.
func TestTimestampsAreComparableRegardlessOfTheCallersZone(t *testing.T) {
	t.Parallel()

	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("the time zone database is unavailable: %v", err)
	}

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			u := newUser(t, db, "alice", store.RoleAdmin)

			// An expiry an hour in the past, expressed in a non-UTC zone.
			expired := time.Now().In(tokyo).Add(-time.Hour)
			newSession(t, db, u.ID, "stale", expired)

			if _, err := db.Sessions().Lookup(t.Context(), "stale", time.Hour); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("a session that expired an hour ago was accepted: %v", err)
			}

			// And one an hour in the future, also in a non-UTC zone.
			future := time.Now().In(tokyo).Add(time.Hour)
			newSession(t, db, u.ID, "fresh", future)

			if _, err := db.Sessions().Lookup(t.Context(), "fresh", time.Hour); err != nil {
				t.Errorf("a session valid for another hour was rejected: %v", err)
			}
		})
	}
}

func TestAuditAppendAndList(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)

			entries := []*store.AuditEntry{
				{
					ActorType: store.ActorUser, ActorID: "u1", ActorName: "alice",
					Action: "mailbox.create", TargetType: "mailbox", TargetID: "mb-1",
					TargetName: "sales@example.com", IP: "10.0.0.5",
				},
				{
					ActorType: store.ActorUser, ActorID: "u2", ActorName: "bob",
					Action: "account.delete", TargetType: "smtp_account", TargetID: "acct-1",
					Result: store.ResultFailure,
				},
			}
			for _, e := range entries {
				if err := db.Audit().Append(t.Context(), e); err != nil {
					t.Fatalf("Append: %v", err)
				}
				if e.ID == "" || e.At.IsZero() {
					t.Errorf("Append did not stamp the entry: %+v", e)
				}
			}

			all, err := db.Audit().List(t.Context(), store.AuditFilter{})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(all) != 2 {
				t.Fatalf("List returned %d entries, want 2", len(all))
			}

			byActor, err := db.Audit().List(t.Context(), store.AuditFilter{ActorID: "u1"})
			if err != nil || len(byActor) != 1 {
				t.Errorf("List by actor = (%d, %v), want 1", len(byActor), err)
			}
			byTarget, err := db.Audit().List(t.Context(), store.AuditFilter{TargetType: "mailbox"})
			if err != nil || len(byTarget) != 1 {
				t.Errorf("List by target type = (%d, %v), want 1", len(byTarget), err)
			}
			byAction, err := db.Audit().List(t.Context(), store.AuditFilter{Action: "account.delete"})
			if err != nil || len(byAction) != 1 {
				t.Errorf("List by action = (%d, %v), want 1", len(byAction), err)
			}

			n, err := db.Audit().Count(t.Context(), store.AuditFilter{})
			if err != nil || n != 2 {
				t.Errorf("Count = (%d, %v), want 2", n, err)
			}
		})
	}
}

func TestMaskSecrets(t *testing.T) {
	t.Parallel()

	// The audit log records what changed, not the values. A rotated client
	// secret sitting in an append-only table would outlive the rotation.
	details := map[string]any{
		"name":              "primary",
		"clientSecret":      "super-secret",
		"client_secret_enc": "v1.k1.sealed",
		"newPassword":       "hunter2",
		"totp_secret":       "JBSWY3DP",
		"accessToken":       "T0K3N",
		"apiKey":            "abc",
		"emptySecret":       "",
		"nilSecret":         nil,
		"nested": map[string]any{
			"passwordHash": "$argon2id$...",
			"transport":    "smtp",
		},
		"list": []any{
			map[string]any{"secret": "also-secret", "keep": "visible"},
		},
	}

	got := store.MaskSecrets(details)

	for _, leaked := range []string{
		"super-secret", "v1.k1.sealed", "hunter2", "JBSWY3DP", "T0K3N",
		"$argon2id$", "also-secret",
	} {
		if strings.Contains(got, leaked) {
			t.Errorf("the audit details leaked %q:\n%s", leaked, got)
		}
	}
	// Everything that is not secret must survive, or the entry says nothing.
	for _, kept := range []string{"primary", "smtp", "visible"} {
		if !strings.Contains(got, kept) {
			t.Errorf("the audit details lost %q:\n%s", kept, got)
		}
	}
	// Whether a secret was set at all is worth recording.
	if !strings.Contains(got, "(unset)") || !strings.Contains(got, "(redacted)") {
		t.Errorf("the mask did not distinguish set from unset:\n%s", got)
	}
}

func TestMaskSecretsHandlesUnencodableValues(t *testing.T) {
	t.Parallel()

	// Losing the detail is acceptable; losing the entry is not.
	got := store.MaskSecrets(map[string]any{"bad": make(chan int)})
	if got == "" {
		t.Error("MaskSecrets returned nothing for an unencodable value")
	}
	if !strings.Contains(got, "error") {
		t.Errorf("MaskSecrets = %q, want it to say the details could not be encoded", got)
	}
}
