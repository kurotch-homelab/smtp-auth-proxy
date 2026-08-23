// Package store owns the database: schema migrations, connection setup and the
// repositories the rest of the proxy reads and writes through.
//
// Both SQLite and PostgreSQL are supported. Rather than maintaining two sets of
// queries, statements are written once with `?` placeholders and rebound for
// PostgreSQL; the handful of statements that genuinely differ between the two
// engines go through the Dialect interface below.
package store

import (
	"fmt"
	"strings"
)

// Dialect abstracts the parts of SQL the two engines disagree about.
type Dialect interface {
	// Name is "sqlite" or "postgres".
	Name() string
	// Rebind converts `?` placeholders to the engine's own form.
	Rebind(query string) string
	// LockClause returns the clause that claims rows for one worker.
	LockClause() string
	// Now returns the engine's current-timestamp expression.
	Now() string
	// IsUniqueViolation reports whether err is a duplicate-key error, so callers
	// can turn it into a friendly "that name is already in use".
	IsUniqueViolation(err error) bool
	// IsForeignKeyViolation reports whether err is a foreign-key failure.
	IsForeignKeyViolation(err error) bool
}

// DialectFor returns the dialect for a driver name.
func DialectFor(driver string) (Dialect, error) {
	switch driver {
	case DriverSQLite:
		return sqliteDialect{}, nil
	case DriverPostgres:
		return postgresDialect{}, nil
	default:
		return nil, fmt.Errorf("store: unknown driver %q", driver)
	}
}

// Driver names, kept in sync with the config package's values.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// rebindDollar rewrites `?` placeholders as $1, $2, ... It deliberately
// understands SQL string literals so that a `?` inside quoted text is left
// alone.
func rebindDollar(query string) string {
	var out strings.Builder
	out.Grow(len(query) + 8)

	n := 0
	inSingle, inDouble := false, false

	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case inSingle:
			out.WriteByte(c)
			if c == '\'' {
				// '' is an escaped quote inside a literal.
				if i+1 < len(query) && query[i+1] == '\'' {
					out.WriteByte('\'')
					i++
					continue
				}
				inSingle = false
			}
			continue
		case inDouble:
			out.WriteByte(c)
			if c == '"' {
				inDouble = false
			}
			continue
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '?':
			n++
			out.WriteByte('$')
			out.WriteString(itoa(n))
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

// itoa avoids pulling strconv into a hot path for small positive integers.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
