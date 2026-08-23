package store_test

import (
	"errors"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

// expectedTables must list every table the initial schema creates. Adding a
// table without updating this list fails the test, which is the point: it is
// how the two dialects are kept honest.
var expectedTables = []string{
	"admin_sessions",
	"admin_users",
	"allowed_senders",
	"audit_logs",
	"mailboxes",
	"message_blobs",
	"messages",
	"oauth_credentials",
	"schema_migrations",
	"smtp_account_mailboxes",
	"smtp_accounts",
}

func TestMigrateUp(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.OpenUnmigrated(t, driver)
			m := store.NewMigrator(db.DB, db.Dialect())

			applied, err := m.Up(t.Context())
			if err != nil {
				t.Fatalf("Up: %v", err)
			}
			if applied == 0 {
				t.Fatal("Up applied no migrations")
			}

			// Running again must be a no-op, not an error: every replica calls
			// this at startup.
			again, err := m.Up(t.Context())
			if err != nil {
				t.Fatalf("second Up: %v", err)
			}
			if again != 0 {
				t.Errorf("second Up applied %d migrations, want 0", again)
			}

			for _, table := range expectedTables {
				assertTableExists(t, db, table)
			}
		})
	}
}

func TestMigrateDownAndUpAgain(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			m := store.NewMigrator(db.DB, db.Dialect())

			reverted, err := m.Down(t.Context(), 0)
			if err != nil {
				t.Fatalf("Down: %v", err)
			}
			if reverted == 0 {
				t.Fatal("Down reverted nothing")
			}

			// Every table except the migration bookkeeping must be gone.
			for _, table := range expectedTables {
				if table == "schema_migrations" {
					continue
				}
				assertTableMissing(t, db, table)
			}

			applied, err := m.Up(t.Context())
			if err != nil {
				t.Fatalf("Up after Down: %v", err)
			}
			if applied != reverted {
				t.Errorf("re-applied %d migrations, want %d", applied, reverted)
			}
			for _, table := range expectedTables {
				assertTableExists(t, db, table)
			}
		})
	}
}

func TestMigrateDownRejectsImpossibleTarget(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	m := store.NewMigrator(db.DB, db.Dialect())

	if _, err := m.Down(t.Context(), 99); err == nil {
		t.Error("Down to a version beyond the current one = nil error, want error")
	}
	if _, err := m.Down(t.Context(), -1); err == nil {
		t.Error("Down to a negative version = nil error, want error")
	}
}

func TestMigrateDetectsAnEditedMigration(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)

	// Simulate someone editing a migration that has already run.
	_, err := db.ExecContext(t.Context(),
		db.Rebind(`UPDATE schema_migrations SET checksum = ? WHERE version = 1`), "tampered")
	if err != nil {
		t.Fatalf("updating the checksum: %v", err)
	}

	m := store.NewMigrator(db.DB, db.Dialect())
	if _, err := m.Up(t.Context()); !errors.Is(err, store.ErrDirtySchema) {
		t.Errorf("Up = %v, want ErrDirtySchema", err)
	}
}

func TestMigrateRefusesASchemaFromTheFuture(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)

	// A newer replica has already migrated past what this binary knows.
	_, err := db.ExecContext(t.Context(), db.Rebind(
		`INSERT INTO schema_migrations (version, name, checksum, applied_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`), 999, "from_the_future", "x")
	if err != nil {
		t.Fatalf("inserting a future migration: %v", err)
	}

	m := store.NewMigrator(db.DB, db.Dialect())
	if _, err := m.Up(t.Context()); !errors.Is(err, store.ErrSchemaAhead) {
		t.Errorf("Up = %v, want ErrSchemaAhead", err)
	}
}

func TestAppliedRecordsEveryMigration(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			m := store.NewMigrator(db.DB, db.Dialect())

			applied, err := m.Applied(t.Context())
			if err != nil {
				t.Fatalf("Applied: %v", err)
			}
			want, err := store.LoadMigrations(driver)
			if err != nil {
				t.Fatalf("LoadMigrations: %v", err)
			}
			if len(applied) != len(want) {
				t.Fatalf("Applied returned %d rows, want %d", len(applied), len(want))
			}
			for i, a := range applied {
				if a.Version != want[i].Version || a.Name != want[i].Name || a.Checksum != want[i].Checksum {
					t.Errorf("row %d = %+v, want version %d name %q", i, a, want[i].Version, want[i].Name)
				}
				if a.AppliedAt.IsZero() {
					t.Errorf("row %d has a zero applied_at", i)
				}
			}
		})
	}
}

// The schema relies on ON DELETE CASCADE, which SQLite ignores unless
// foreign_keys is switched on for the connection.
func TestForeignKeysAreEnforced(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)

			_, err := db.ExecContext(t.Context(), db.Rebind(
				`INSERT INTO mailboxes (id, address, oauth_credential_id, transport, created_at, updated_at)
				 VALUES (?, ?, ?, 'smtp', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`),
				"m1", "shared@example.com", "does-not-exist")
			if err == nil {
				t.Fatal("inserted a mailbox referencing a missing credential; foreign keys are not enforced")
			}
			if !db.Dialect().IsForeignKeyViolation(err) {
				t.Errorf("IsForeignKeyViolation did not recognize the error: %v", err)
			}
		})
	}
}

func TestUniqueViolationIsRecognised(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			insert := db.Rebind(
				`INSERT INTO oauth_credentials (id, name, tenant_id, client_id, auth_type, created_at, updated_at)
				 VALUES (?, ?, 'tenant', 'client', 'secret', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)

			if _, err := db.ExecContext(t.Context(), insert, "c1", "primary"); err != nil {
				t.Fatalf("first insert: %v", err)
			}
			_, err := db.ExecContext(t.Context(), insert, "c2", "primary")
			if err == nil {
				t.Fatal("inserted a duplicate credential name")
			}
			if !db.Dialect().IsUniqueViolation(err) {
				t.Errorf("IsUniqueViolation did not recognize the error: %v", err)
			}
		})
	}
}

func assertTableExists(t *testing.T, db *store.DB, table string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), "SELECT 1 FROM "+table+" WHERE 1 = 0"); err != nil {
		t.Errorf("table %s is missing: %v", table, err)
	}
}

func assertTableMissing(t *testing.T, db *store.DB, table string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), "SELECT 1 FROM "+table+" WHERE 1 = 0"); err == nil {
		t.Errorf("table %s still exists after rolling back", table)
	}
}
