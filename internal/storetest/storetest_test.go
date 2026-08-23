package storetest_test

import (
	"os"
	"slices"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func TestDriversCoversBothEngines(t *testing.T) {
	t.Parallel()

	got := storetest.Drivers()
	for _, want := range []string{store.DriverSQLite, store.DriverPostgres} {
		if !slices.Contains(got, want) {
			t.Errorf("Drivers() = %v, want it to include %q", got, want)
		}
	}
}

func TestOpenReturnsAMigratedDatabase(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			if db.Dialect().Name() != driver {
				t.Errorf("Dialect().Name() = %q, want %q", db.Dialect().Name(), driver)
			}

			// Open must hand back a schema that is ready to use.
			var n int
			err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM mailboxes").Scan(&n)
			if err != nil {
				t.Fatalf("querying a migrated table: %v", err)
			}
			if n != 0 {
				t.Errorf("a fresh test database already has %d mailboxes", n)
			}
		})
	}
}

func TestOpenUnmigratedHasNoSchema(t *testing.T) {
	t.Parallel()

	db := storetest.OpenUnmigrated(t, store.DriverSQLite)
	if _, err := db.ExecContext(t.Context(), "SELECT 1 FROM mailboxes"); err == nil {
		t.Error("OpenUnmigrated returned a database that already has the schema")
	}
}

func TestEachTestGetsItsOwnDatabase(t *testing.T) {
	t.Parallel()

	// Tests must not be able to see each other's rows, or a parallel run would
	// be flaky in ways that are painful to debug.
	a := storetest.Open(t, store.DriverSQLite)
	b := storetest.Open(t, store.DriverSQLite)

	insert := a.Rebind(
		`INSERT INTO oauth_credentials (id, name, tenant_id, client_id, auth_type, created_at, updated_at)
		 VALUES (?, 'x', 't', 'c', 'secret', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if _, err := a.ExecContext(t.Context(), insert, "id-1"); err != nil {
		t.Fatalf("insert into the first database: %v", err)
	}

	var n int
	if err := b.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM oauth_credentials").Scan(&n); err != nil {
		t.Fatalf("counting in the second database: %v", err)
	}
	if n != 0 {
		t.Errorf("the second database sees %d rows written to the first", n)
	}
}

func TestPostgresVariantSkipsWithoutADSN(t *testing.T) {
	// Not parallel: it manipulates the environment.
	if os.Getenv(storetest.PostgresDSNEnv) != "" {
		t.Skipf("%s is set, so the skip path cannot be exercised", storetest.PostgresDSNEnv)
	}

	// With no DSN configured the helper must skip rather than fail, so the suite
	// still passes on a machine with no PostgreSQL.
	sub := t.Run("inner", func(t *testing.T) {
		storetest.Open(t, store.DriverPostgres)
		t.Error("expected the helper to skip")
	})
	if !sub {
		t.Error("the inner test failed instead of skipping")
	}
}
