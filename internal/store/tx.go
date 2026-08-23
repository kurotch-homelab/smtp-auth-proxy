package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Tx is a transaction that knows its dialect, so callers can keep using
// `?` placeholders inside one.
type Tx struct {
	*sql.Tx
	dialect Dialect
}

// Rebind converts `?` placeholders for the underlying engine.
func (t *Tx) Rebind(query string) string { return t.dialect.Rebind(query) }

// InTx runs fn inside a transaction, committing when it returns nil and rolling
// back otherwise. A panic also rolls back before it continues unwinding.
//
// Note that a transaction is not how the queue claims work. SQLite promotes a
// transaction from read to write on its first write, and that promotion can
// fail after the reads have already succeeded; claiming is therefore done with
// a single atomic UPDATE instead. See ClaimMessages.
func (db *DB) InTx(ctx context.Context, fn func(*Tx) error) error {
	return db.inTx(ctx, nil, fn)
}

func (db *DB) inTx(ctx context.Context, opts *sql.TxOptions, fn func(*Tx) error) error {
	sqlTx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	tx := &Tx{Tx: sqlTx, dialect: db.dialect}

	defer func() {
		if p := recover(); p != nil {
			_ = sqlTx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		_ = sqlTx.Rollback()
		return err
	}
	if err := sqlTx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
