// Package discardlog provides a logger that throws everything away, for tests
// that assert on behavior rather than on what was logged.
package discardlog

import (
	"io"
	"log/slog"
)

// Logger returns a logger that writes nowhere.
func Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
