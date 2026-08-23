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
	switch sqliteErrorCode(err) {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	default:
		return false
	}
}

// IsForeignKeyViolation accepts two extended codes, because SQLite reports the
// two directions differently: inserting a child row that points at nothing gives
// SQLITE_CONSTRAINT_FOREIGNKEY, while deleting a parent row that something still
// references gives SQLITE_CONSTRAINT_TRIGGER — immediate foreign-key actions are
// implemented internally as triggers. Both carry the message
// "FOREIGN KEY constraint failed", and this schema defines no triggers of its
// own, so treating both as a foreign-key violation is unambiguous.
func (sqliteDialect) IsForeignKeyViolation(err error) bool {
	switch sqliteErrorCode(err) {
	case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY, sqlite3.SQLITE_CONSTRAINT_TRIGGER:
		return true
	default:
		return false
	}
}

func sqliteErrorCode(err error) int {
	var serr *sqlite.Error
	if errors.As(err, &serr) {
		return serr.Code()
	}
	return 0
}
