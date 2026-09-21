// Package legal serves the same notices in the binary and every distribution.
package legal

import (
	_ "embed"
	"net/http"
)

// Notices includes the application's notices and all distributed dependencies.
//
//go:embed THIRD_PARTY_NOTICES.txt
var Notices string

// Handler is public so licenses remain accessible before sign-in.
func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="THIRD_PARTY_NOTICES.txt"`)
	}
	_, _ = w.Write([]byte(Notices))
}
