package adminapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// listResponse is the envelope for every collection endpoint, so the UI has one
// shape to render and pagination is always available.
type listResponse[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

// queryInt reads an integer query parameter, falling back on anything invalid
// rather than failing the request: a malformed limit is not worth a 400.
func queryInt(r *http.Request, name string, fallback int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

// queryTime reads an RFC 3339 timestamp.
func queryTime(r *http.Request, name string) (time.Time, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// queryList reads a repeated or comma-separated query parameter.
func queryList(r *http.Request, name string) []string {
	values := r.URL.Query()[name]
	out := make([]string, 0, len(values))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
