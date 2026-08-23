package store

import "strings"

// splitColumns turns a formatted column list into its individual names.
func splitColumns(columns string) []string {
	parts := strings.Split(columns, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
