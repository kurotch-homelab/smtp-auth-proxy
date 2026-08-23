package store

import (
	"encoding/json"
	"fmt"
)

// Short lists — recipients, allowed CIDRs — are stored as JSON text rather than
// in side tables. They are always read and written whole, never queried by
// element, so a join would buy nothing.

func marshalList(v []string) (string, error) {
	if len(v) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("store: encoding list: %w", err)
	}
	return string(b), nil
}

func unmarshalList(s string) ([]string, error) {
	if s == "" || s == "[]" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("store: decoding list %q: %w", s, err)
	}
	return out, nil
}
