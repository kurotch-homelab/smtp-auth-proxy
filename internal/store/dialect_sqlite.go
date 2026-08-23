package store

import (
	"errors"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type sqliteDialect struct{}

func (sqliteDialect) Name() string { return DriverSQLite }

// Rebind is a no-op: SQLite uses `?` natively.
func (sqliteDialect) Rebind(q string) string { return q }

// LockClause is empty because SQLite serializes writers itself. Claiming a
// message is instead done inside an immediate transaction, which takes the
// write lock up front.
func (sqliteDialect) LockClause() string { return "" }

func (sqliteDialect) Now() string { return "CURRENT_TIMESTAMP" }

func (sqliteDialect) IsUniqueViolation(err error) bool {
	return sqliteErrorCode(err) == sqlite3.SQLITE_CONSTRAINT_UNIQUE ||
		sqliteErrorCode(err) == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

func (sqliteDialect) IsForeignKeyViolation(err error) bool {
	return sqliteErrorCode(err) == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY
}

func sqliteErrorCode(err error) int {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		return serr.Code()
	}
	return 0
}
