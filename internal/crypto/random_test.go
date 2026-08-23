package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGeneratedSecretsAreUniqueAndDecodable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		gen       func() (string, error)
		wantBytes int
	}{
		{"password", GeneratePassword, passwordEntropyBytes},
		{"token", GenerateToken, tokenEntropyBytes},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			seen := make(map[string]struct{}, 128)
			for range 128 {
				got, err := tt.gen()
				if err != nil {
					t.Fatalf("generate: %v", err)
				}
				if _, dup := seen[got]; dup {
					t.Fatalf("generated a duplicate value: %q", got)
				}
				seen[got] = struct{}{}

				raw, err := base64.RawURLEncoding.DecodeString(got)
				if err != nil {
					t.Fatalf("value is not base64url: %q", got)
				}
				if len(raw) != tt.wantBytes {
					t.Fatalf("decoded to %d bytes, want %d", len(raw), tt.wantBytes)
				}
			}
		})
	}
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"token", "token", true},
		{"token", "toke", false},
		{"token", "tokeN", false},
		{"token", "", false},
		{"", "token", false},
	}

	for _, tt := range tests {
		if got := ConstantTimeEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("ConstantTimeEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
