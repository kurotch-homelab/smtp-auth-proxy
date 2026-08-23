package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationFiles embed.FS

// Migration errors.
var (
	// ErrDirtySchema means a migration was edited after it was applied. Silently
	// continuing would leave the database in a state nobody can reproduce.
	ErrDirtySchema = errors.New("store: an applied migration has been modified since it ran")
	// ErrSchemaAhead means the database has migrations this binary does not know
	// about, which happens when an older replica starts during a rollout.
	ErrSchemaAhead = errors.New("store: database schema is newer than this binary")
)

// Migration is one versioned schema change.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
	// Checksum covers the Up statement so a later edit can be detected.
	Checksum string
}

// AppliedMigration records a migration that has run.
type AppliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt time.Time
}

// LoadMigrations reads the embedded migrations for a dialect, sorted by version.
func LoadMigrations(dialect string) ([]Migration, error) {
	dir := path.Join("migrations", dialect)
	entries, err := fs.ReadDir(migrationFiles, dir)
	if err != nil {
		return nil, fmt.Errorf("store: no migrations for dialect %q: %w", dialect, err)
	}

	byVersion := map[int]*Migration{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		version, name, direction, err := parseMigrationName(e.Name())
		if err != nil {
			return nil, err
		}

		body, err := fs.ReadFile(migrationFiles, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("store: reading %s: %w", e.Name(), err)
		}

		m, ok := byVersion[version]
		if !ok {
			m = &Migration{Version: version, Name: name}
			byVersion[version] = m
		}
		if m.Name != name {
			return nil, fmt.Errorf("store: migration %04d has conflicting names %q and %q", version, m.Name, name)
		}
		if direction == "up" {
			m.Up = string(body)
			sum := sha256.Sum256(body)
			m.Checksum = hex.EncodeToString(sum[:])
		} else {
			m.Down = string(body)
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == "" {
			return nil, fmt.Errorf("store: migration %04d_%s has no .up.sql", m.Version, m.Name)
		}
		if m.Down == "" {
			return nil, fmt.Errorf("store: migration %04d_%s has no .down.sql", m.Version, m.Name)
		}
		out = append(out, *m)
	}
	slices.SortFunc(out, func(a, b Migration) int { return a.Version - b.Version })

	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("store: migration versions must be contiguous from 1; found %04d at position %d", m.Version, i+1)
		}
	}
	return out, nil
}

// parseMigrationName splits "0001_initial_schema.up.sql".
func parseMigrationName(filename string) (version int, name, direction string, err error) {
	base, ok := strings.CutSuffix(filename, ".sql")
	if !ok {
		return 0, "", "", fmt.Errorf("store: migration %q must end in .sql", filename)
	}

	base, direction, err = cutDirection(base, filename)
	if err != nil {
		return 0, "", "", err
	}

	versionStr, name, ok := strings.Cut(base, "_")
	if !ok || name == "" {
		return 0, "", "", fmt.Errorf("store: migration %q must be named <version>_<name>.<up|down>.sql", filename)
	}
	version, err = strconv.Atoi(versionStr)
	if err != nil || version <= 0 {
		return 0, "", "", fmt.Errorf("store: migration %q has an invalid version %q", filename, versionStr)
	}
	return version, name, direction, nil
}

func cutDirection(base, filename string) (rest, direction string, err error) {
	if rest, ok := strings.CutSuffix(base, ".up"); ok {
		return rest, "up", nil
	}
	if rest, ok := strings.CutSuffix(base, ".down"); ok {
		return rest, "down", nil
	}
	return "", "", fmt.Errorf("store: migration %q must end in .up.sql or .down.sql", filename)
}

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER   NOT NULL PRIMARY KEY,
	name       TEXT      NOT NULL,
	checksum   TEXT      NOT NULL,
	applied_at TIMESTAMP NOT NULL
)`

// Migrator applies schema migrations.
type Migrator struct {
	db      *sql.DB
	dialect Dialect
}

// NewMigrator returns a migrator for an open database.
func NewMigrator(db *sql.DB, dialect Dialect) *Migrator {
	return &Migrator{db: db, dialect: dialect}
}

// Applied lists the migrations recorded in the database, oldest first.
func (m *Migrator) Applied(ctx context.Context) ([]AppliedMigration, error) {
	if _, err := m.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("store: creating schema_migrations: %w", err)
	}

	rows, err := m.db.QueryContext(ctx,
		`SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("store: reading schema_migrations: %w", err)
	}
	defer rows.Close()

	var out []AppliedMigration
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, fmt.Errorf("store: scanning schema_migrations: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Up applies every pending migration and returns how many ran.
func (m *Migrator) Up(ctx context.Context) (int, error) {
	migrations, err := LoadMigrations(m.dialect.Name())
	if err != nil {
		return 0, err
	}
	applied, err := m.Applied(ctx)
	if err != nil {
		return 0, err
	}
	if err := verifyApplied(migrations, applied); err != nil {
		return 0, err
	}

	ran := 0
	for _, mig := range migrations[len(applied):] {
		if err := m.runUp(ctx, mig); err != nil {
			return ran, err
		}
		ran++
	}
	return ran, nil
}

// verifyApplied checks that what ran matches what this binary carries.
func verifyApplied(migrations []Migration, applied []AppliedMigration) error {
	if len(applied) > len(migrations) {
		return fmt.Errorf("%w: database is at version %d, this binary knows %d",
			ErrSchemaAhead, applied[len(applied)-1].Version, len(migrations))
	}
	for i, a := range applied {
		want := migrations[i]
		if a.Version != want.Version || a.Name != want.Name {
			return fmt.Errorf("%w: version %d is recorded as %q but this binary has %q",
				ErrDirtySchema, a.Version, a.Name, want.Name)
		}
		if a.Checksum != want.Checksum {
			return fmt.Errorf("%w: %04d_%s (recorded %s, computed %s)",
				ErrDirtySchema, a.Version, a.Name, short(a.Checksum), short(want.Checksum))
		}
	}
	return nil
}

func short(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

func (m *Migrator) runUp(ctx context.Context, mig Migration) error {
	// Each migration runs in its own transaction, so a failure leaves the
	// database at the last complete version rather than half-migrated.
	return m.inTx(ctx, func(tx *sql.Tx) error {
		if err := execScript(ctx, tx, mig.Up); err != nil {
			return fmt.Errorf("store: applying %04d_%s: %w", mig.Version, mig.Name, err)
		}
		_, err := tx.ExecContext(ctx, m.dialect.Rebind(
			`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`),
			mig.Version, mig.Name, mig.Checksum, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("store: recording %04d_%s: %w", mig.Version, mig.Name, err)
		}
		return nil
	})
}

// Down rolls back to the given version, which may be 0 for an empty schema.
func (m *Migrator) Down(ctx context.Context, target int) (int, error) {
	migrations, err := LoadMigrations(m.dialect.Name())
	if err != nil {
		return 0, err
	}
	applied, err := m.Applied(ctx)
	if err != nil {
		return 0, err
	}
	if err := verifyApplied(migrations, applied); err != nil {
		return 0, err
	}
	if target < 0 || target > len(applied) {
		return 0, fmt.Errorf("store: cannot roll back to version %d; database is at %d", target, len(applied))
	}

	reverted := 0
	for i := len(applied) - 1; i >= target; i-- {
		mig := migrations[i]
		err := m.inTx(ctx, func(tx *sql.Tx) error {
			if err := execScript(ctx, tx, mig.Down); err != nil {
				return fmt.Errorf("store: reverting %04d_%s: %w", mig.Version, mig.Name, err)
			}
			_, err := tx.ExecContext(ctx,
				m.dialect.Rebind(`DELETE FROM schema_migrations WHERE version = ?`), mig.Version)
			return err
		})
		if err != nil {
			return reverted, err
		}
		reverted++
	}
	return reverted, nil
}

func (m *Migrator) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// execScript runs a migration file one statement at a time.
//
// SQLite's driver only executes a single statement per Exec, so multi-statement
// files have to be split. Splitting is done on `;` at the end of a line, which
// is why migrations must not embed a semicolon-terminated line inside a string
// literal or a trigger body without the marker below.
func execScript(ctx context.Context, tx *sql.Tx, script string) error {
	for _, stmt := range splitStatements(script) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w\nstatement: %s", err, firstLine(stmt))
		}
	}
	return nil
}

func splitStatements(script string) []string {
	var (
		out      []string
		current  strings.Builder
		inSingle bool
	)

	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		// Skip whole-line comments so they never form an empty statement.
		if !inSingle && (trimmed == "" || strings.HasPrefix(trimmed, "--")) {
			continue
		}

		current.WriteString(line)
		current.WriteString("\n")

		// Track quoting so a `;` inside a string literal does not split.
		for i := 0; i < len(line); i++ {
			if line[i] != '\'' {
				continue
			}
			if inSingle && i+1 < len(line) && line[i+1] == '\'' {
				i++
				continue
			}
			inSingle = !inSingle
		}

		if !inSingle && strings.HasSuffix(trimmed, ";") {
			if s := strings.TrimSpace(current.String()); s != "" {
				out = append(out, s)
			}
			current.Reset()
		}
	}

	if s := strings.TrimSpace(current.String()); s != "" {
		out = append(out, s)
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
