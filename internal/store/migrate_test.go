package store

import (
	"strings"
	"testing"
)

func TestParseMigrationName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename      string
		wantVersion   int
		wantName      string
		wantDirection string
		wantErr       string
	}{
		{filename: "0001_initial_schema.up.sql", wantVersion: 1, wantName: "initial_schema", wantDirection: "up"},
		{filename: "0001_initial_schema.down.sql", wantVersion: 1, wantName: "initial_schema", wantDirection: "down"},
		{filename: "0042_add_index.up.sql", wantVersion: 42, wantName: "add_index", wantDirection: "up"},

		{filename: "0001_initial.sql", wantErr: "must end in .up.sql or .down.sql"},
		{filename: "0001_initial.up.txt", wantErr: "must end in .sql"},
		{filename: "initial.up.sql", wantErr: "<version>_<name>"},
		{filename: "abc_name.up.sql", wantErr: "invalid version"},
		{filename: "0001.up.sql", wantErr: "<version>_<name>"},
		{filename: "0000_zero.up.sql", wantErr: "invalid version"},
		{filename: "-1_negative.up.sql", wantErr: "invalid version"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			t.Parallel()

			version, name, direction, err := parseMigrationName(tt.filename)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseMigrationName(%q) = nil error, want error", tt.filename)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMigrationName(%q): %v", tt.filename, err)
			}
			if version != tt.wantVersion || name != tt.wantName || direction != tt.wantDirection {
				t.Errorf("= (%d, %q, %q), want (%d, %q, %q)",
					version, name, direction, tt.wantVersion, tt.wantName, tt.wantDirection)
			}
		})
	}
}

func TestLoadMigrationsForEveryDialect(t *testing.T) {
	t.Parallel()

	for _, dialect := range []string{DriverSQLite, DriverPostgres} {
		t.Run(dialect, func(t *testing.T) {
			t.Parallel()

			migrations, err := LoadMigrations(dialect)
			if err != nil {
				t.Fatalf("LoadMigrations(%q): %v", dialect, err)
			}
			if len(migrations) == 0 {
				t.Fatalf("LoadMigrations(%q) returned nothing", dialect)
			}
			for i, m := range migrations {
				if m.Version != i+1 {
					t.Errorf("migration %d has version %d, want %d", i, m.Version, i+1)
				}
				if strings.TrimSpace(m.Up) == "" || strings.TrimSpace(m.Down) == "" {
					t.Errorf("%04d_%s has an empty up or down script", m.Version, m.Name)
				}
				if m.Checksum == "" {
					t.Errorf("%04d_%s has no checksum", m.Version, m.Name)
				}
			}
		})
	}
}

// The two dialects must stay structurally identical: a table or migration added
// to one and forgotten in the other would only surface in production.
func TestDialectsHaveMatchingMigrations(t *testing.T) {
	t.Parallel()

	sqliteMigrations, err := LoadMigrations(DriverSQLite)
	if err != nil {
		t.Fatalf("LoadMigrations(sqlite): %v", err)
	}
	postgresMigrations, err := LoadMigrations(DriverPostgres)
	if err != nil {
		t.Fatalf("LoadMigrations(postgres): %v", err)
	}

	if len(sqliteMigrations) != len(postgresMigrations) {
		t.Fatalf("sqlite has %d migrations, postgres has %d",
			len(sqliteMigrations), len(postgresMigrations))
	}
	for i := range sqliteMigrations {
		if sqliteMigrations[i].Name != postgresMigrations[i].Name {
			t.Errorf("migration %d: sqlite is %q, postgres is %q",
				i+1, sqliteMigrations[i].Name, postgresMigrations[i].Name)
		}
	}
}

func TestLoadMigrationsRejectsUnknownDialect(t *testing.T) {
	t.Parallel()

	if _, err := LoadMigrations("mysql"); err == nil {
		t.Error("LoadMigrations(mysql) = nil error, want error")
	}
}

func TestVerifyApplied(t *testing.T) {
	t.Parallel()

	migrations := []Migration{
		{Version: 1, Name: "initial", Checksum: "aaa"},
		{Version: 2, Name: "second", Checksum: "bbb"},
	}

	tests := []struct {
		name    string
		applied []AppliedMigration
		wantErr error
	}{
		{
			name:    "nothing applied",
			applied: nil,
		},
		{
			name:    "prefix applied",
			applied: []AppliedMigration{{Version: 1, Name: "initial", Checksum: "aaa"}},
		},
		{
			name: "all applied",
			applied: []AppliedMigration{
				{Version: 1, Name: "initial", Checksum: "aaa"},
				{Version: 2, Name: "second", Checksum: "bbb"},
			},
		},
		{
			// An edited migration means the schema in the database is not the
			// one in this binary, and nobody can say what it actually contains.
			name:    "checksum changed",
			applied: []AppliedMigration{{Version: 1, Name: "initial", Checksum: "different"}},
			wantErr: ErrDirtySchema,
		},
		{
			name:    "renamed migration",
			applied: []AppliedMigration{{Version: 1, Name: "renamed", Checksum: "aaa"}},
			wantErr: ErrDirtySchema,
		},
		{
			// An older replica starting mid-rollout must refuse rather than run
			// against a schema it does not understand.
			name: "database ahead of the binary",
			applied: []AppliedMigration{
				{Version: 1, Name: "initial", Checksum: "aaa"},
				{Version: 2, Name: "second", Checksum: "bbb"},
				{Version: 3, Name: "future", Checksum: "ccc"},
			},
			wantErr: ErrSchemaAhead,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := verifyApplied(migrations, tt.applied)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("verifyApplied = %v, want nil", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("verifyApplied = nil, want %v", tt.wantErr)
			case tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErr.Error()):
				t.Errorf("verifyApplied = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSplitStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "single statement",
			in:   "CREATE TABLE t (id TEXT);",
			want: []string{"CREATE TABLE t (id TEXT);"},
		},
		{
			name: "two statements",
			in:   "CREATE TABLE a (id TEXT);\nCREATE TABLE b (id TEXT);",
			want: []string{"CREATE TABLE a (id TEXT);", "CREATE TABLE b (id TEXT);"},
		},
		{
			name: "comments and blank lines are dropped",
			in:   "-- a comment\n\nCREATE TABLE t (id TEXT);\n\n-- trailing\n",
			want: []string{"CREATE TABLE t (id TEXT);"},
		},
		{
			name: "multi-line statement",
			in:   "CREATE TABLE t (\n\tid TEXT\n);\nCREATE INDEX i ON t (id);",
			want: []string{"CREATE TABLE t (\n\tid TEXT\n);", "CREATE INDEX i ON t (id);"},
		},
		{
			// A semicolon inside a string literal must not split the statement,
			// or a CHECK constraint listing values would be cut in half.
			name: "semicolon inside a string literal",
			in:   "INSERT INTO t VALUES ('a;b');\nINSERT INTO t VALUES ('c');",
			want: []string{"INSERT INTO t VALUES ('a;b');", "INSERT INTO t VALUES ('c');"},
		},
		{
			name: "escaped quote inside a literal",
			in:   "INSERT INTO t VALUES ('it''s; fine');",
			want: []string{"INSERT INTO t VALUES ('it''s; fine');"},
		},
		{
			name: "final statement without a semicolon",
			in:   "CREATE TABLE t (id TEXT)",
			want: []string{"CREATE TABLE t (id TEXT)"},
		},
		{
			name: "empty script",
			in:   "-- nothing here\n",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := splitStatements(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("split into %d statements, want %d:\n%#v", len(got), len(tt.want), got)
			}
			for i := range got {
				if strings.TrimSpace(got[i]) != strings.TrimSpace(tt.want[i]) {
					t.Errorf("statement %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRebindDollar(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"SELECT 1", "SELECT 1"},
		{"SELECT * FROM t WHERE a = ?", "SELECT * FROM t WHERE a = $1"},
		{"INSERT INTO t VALUES (?, ?, ?)", "INSERT INTO t VALUES ($1, $2, $3)"},
		// A question mark inside a literal is data, not a placeholder.
		{"SELECT * FROM t WHERE a = '?' AND b = ?", "SELECT * FROM t WHERE a = '?' AND b = $1"},
		{`SELECT "col?" FROM t WHERE a = ?`, `SELECT "col?" FROM t WHERE a = $1`},
		{"SELECT 'it''s ?' , ?", "SELECT 'it''s ?' , $1"},
	}

	for _, tt := range tests {
		if got := rebindDollar(tt.in); got != tt.want {
			t.Errorf("rebindDollar(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRebindDollarPastTen(t *testing.T) {
	t.Parallel()

	// itoa takes a different branch above nine; make sure it is right.
	query := strings.Repeat("?,", 12)
	got := rebindDollar(query)
	if !strings.Contains(got, "$10,") || !strings.Contains(got, "$12,") {
		t.Errorf("rebindDollar(%q) = %q, want $10 and $12 present", query, got)
	}
}
