package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for PostgreSQL
	_ "modernc.org/sqlite"             // cgo-free database/sql driver for SQLite
)

// Options configure a database connection.
type Options struct {
	Driver          string
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// DB is an open database together with the dialect that describes it.
type DB struct {
	*sql.DB
	dialect Dialect
}

// Dialect returns the SQL dialect for this connection.
func (db *DB) Dialect() Dialect { return db.dialect }

// Rebind converts `?` placeholders for the underlying engine.
func (db *DB) Rebind(query string) string { return db.dialect.Rebind(query) }

// Open connects to the database and verifies the connection.
func Open(ctx context.Context, opts Options) (*DB, error) {
	dialect, err := DialectFor(opts.Driver)
	if err != nil {
		return nil, err
	}

	driverName, dsn, err := driverDSN(opts)
	if err != nil {
		return nil, err
	}

	sqlDB, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening %s database: %w", opts.Driver, err)
	}

	applyPoolSettings(sqlDB, opts)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		// The DSN can contain a password, so it is deliberately not included.
		return nil, fmt.Errorf("store: connecting to the %s database: %w", opts.Driver, err)
	}

	return &DB{DB: sqlDB, dialect: dialect}, nil
}

func driverDSN(opts Options) (driverName, dsn string, err error) {
	switch opts.Driver {
	case DriverSQLite:
		dsn, err = sqliteDSN(opts.DSN)
		return "sqlite", dsn, err
	case DriverPostgres:
		return "pgx", opts.DSN, nil
	default:
		return "", "", fmt.Errorf("store: unknown driver %q", opts.Driver)
	}
}

func applyPoolSettings(db *sql.DB, opts Options) {
	if opts.Driver == DriverSQLite {
		// SQLite in WAL mode allows concurrent readers but only one writer.
		// A small pool plus busy_timeout lets the admin UI read while the queue
		// writes, without the thundering herd a large pool would cause.
		maxOpen := opts.MaxOpenConns
		if maxOpen <= 0 || maxOpen > 8 {
			maxOpen = 4
		}
		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxOpen)
		// Recycling a SQLite connection buys nothing and drops the WAL reader.
		db.SetConnMaxLifetime(0)
		return
	}

	db.SetMaxOpenConns(opts.MaxOpenConns)
	if opts.MaxIdleConns > 0 {
		db.SetMaxIdleConns(opts.MaxIdleConns)
	}
	db.SetConnMaxLifetime(opts.ConnMaxLifetime)
}

// sqlitePragmas are applied to every SQLite connection.
//
//	foreign_keys   SQLite ignores REFERENCES unless this is on, and the schema
//	               relies on ON DELETE CASCADE for sessions and message blobs.
//	journal_mode   WAL lets the admin UI read while the queue writes.
//	busy_timeout   waits instead of failing immediately on a write conflict.
//	synchronous    NORMAL is durable under WAL for everything but a power cut,
//	               and avoids an fsync per transaction.
var sqlitePragmas = []string{
	"foreign_keys(1)",
	"journal_mode(wal)",
	"busy_timeout(5000)",
	"synchronous(normal)",
}

// sqliteDSN turns a plain file path into a DSN with the pragmas applied,
// leaving an explicit file: URI alone apart from adding any missing pragma.
func sqliteDSN(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("store: sqlite dsn must not be empty")
	}

	base, query := raw, ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		base, query = raw[:i], raw[i+1:]
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return "", fmt.Errorf("store: parsing sqlite dsn parameters: %w", err)
	}

	existing := strings.Join(values["_pragma"], " ")
	for _, p := range sqlitePragmas {
		name := p[:strings.IndexByte(p, '(')]
		// Respect a pragma the operator set explicitly.
		if !strings.Contains(existing, name) {
			values.Add("_pragma", p)
		}
	}

	return base + "?" + values.Encode(), nil
}

// Migrate applies any pending schema migrations.
func (db *DB) Migrate(ctx context.Context) (int, error) {
	return NewMigrator(db.DB, db.dialect).Up(ctx)
}
