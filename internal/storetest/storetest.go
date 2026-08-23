// Package storetest opens throwaway databases for tests.
//
// It lives outside internal/store so that importing "testing" — which registers
// command-line flags and bloats any binary that links it — never reaches the
// production build.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// PostgresDSNEnv names the environment variable that points these helpers at a
// live PostgreSQL instance. When it is unset the PostgreSQL variants skip, so
// the suite still runs on a machine with nothing installed.
const PostgresDSNEnv = "TEST_POSTGRES_DSN"

// Drivers returns the drivers store tests should run against.
func Drivers() []string { return []string{store.DriverSQLite, store.DriverPostgres} }

// Open returns a migrated, isolated database for one test.
//
// For sqlite it is a file under t.TempDir() rather than :memory:, because the
// pool opens several connections and each would otherwise get its own empty
// database. For postgres it is a dedicated schema, created and dropped around
// the test so parallel runs cannot see each other's rows.
func Open(t *testing.T, driver string) *store.DB {
	t.Helper()

	db := OpenUnmigrated(t, driver)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrating the %s test database: %v", driver, err)
	}
	return db
}

// OpenUnmigrated is Open without applying migrations, for tests that exercise
// the migrator itself.
func OpenUnmigrated(t *testing.T, driver string) *store.DB {
	t.Helper()

	var opts store.Options
	switch driver {
	case store.DriverSQLite:
		opts = store.Options{
			Driver: store.DriverSQLite,
			DSN:    filepath.Join(t.TempDir(), "test.db"),
		}
	case store.DriverPostgres:
		dsn := os.Getenv(PostgresDSNEnv)
		if dsn == "" {
			t.Skipf("%s is not set; skipping the PostgreSQL variant", PostgresDSNEnv)
		}
		opts = store.Options{Driver: store.DriverPostgres, DSN: dsn, MaxOpenConns: 1}
	default:
		t.Fatalf("unknown driver %q", driver)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	db, err := store.Open(ctx, opts)
	if err != nil {
		t.Fatalf("opening the %s test database: %v", driver, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if driver == store.DriverPostgres {
		isolateSchema(t, db)
	}
	return db
}

// isolateSchema gives a PostgreSQL test its own schema.
func isolateSchema(t *testing.T, db *store.DB) {
	t.Helper()

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generating a schema name: %v", err)
	}
	name := "test_" + hex.EncodeToString(b[:])

	// The pool is already pinned to one connection, so SET search_path applies
	// to every subsequent statement in the test.
	if _, err := db.ExecContext(t.Context(), "CREATE SCHEMA "+name); err != nil {
		t.Fatalf("creating schema %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.WithoutCancel(t.Context()), "DROP SCHEMA "+name+" CASCADE")
	})

	if _, err := db.ExecContext(t.Context(), "SET search_path TO "+name); err != nil {
		t.Fatalf("setting search_path to %s: %v", name, err)
	}
}
