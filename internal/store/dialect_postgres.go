package store

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

type postgresDialect struct{}

func (postgresDialect) Name() string { return DriverPostgres }

func (postgresDialect) Rebind(q string) string { return rebindDollar(q) }

// LockClause lets several replicas poll the queue concurrently: each skips the
// rows another worker already holds instead of blocking behind them.
func (postgresDialect) LockClause() string { return " FOR UPDATE SKIP LOCKED" }

func (postgresDialect) Now() string { return "NOW()" }

// PostgreSQL SQLSTATE codes.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

func (postgresDialect) IsUniqueViolation(err error) bool {
	return pgErrorCode(err) == pgUniqueViolation
}

func (postgresDialect) IsForeignKeyViolation(err error) bool {
	return pgErrorCode(err) == pgForeignKeyViolation
}

func pgErrorCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
