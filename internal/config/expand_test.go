package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newExpander builds an expander over a fixed environment.
func newExpander(env map[string]string) *expander {
	return &expander{
		lookup: func(k string) (string, bool) {
			v, ok := env[k]
			return v, ok
		},
		readFile: os.ReadFile,
	}
}

func TestExpandVariables(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"SECRET": "s3cret",
		"EMPTY":  "",
		"PORT":   "587",
	}

	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "no references", in: "plain text", want: "plain text"},
		{name: "simple reference", in: "${SECRET}", want: "s3cret"},
		{name: "embedded in text", in: "dsn=${SECRET}@host", want: "dsn=s3cret@host"},
		{name: "repeated", in: "${PORT}:${PORT}", want: "587:587"},
		{name: "default when unset", in: "${MISSING:-fallback}", want: "fallback"},
		// An empty environment variable is treated as unset so that an
		// unpopulated Kubernetes Secret falls through to the default rather than
		// silently producing an empty client secret.
		{name: "default when empty", in: "${EMPTY:-fallback}", want: "fallback"},
		{name: "set value beats default", in: "${SECRET:-fallback}", want: "s3cret"},
		{name: "empty default is allowed", in: "x${MISSING:-}y", want: "xy"},
		{name: "escaped dollar", in: "$${NOT_A_VAR}", want: "${NOT_A_VAR}"},
		{name: "lone dollar", in: "cost: $5", want: "cost: $5"},
		{name: "trailing dollar", in: "end$", want: "end$"},
		{name: "dollar without brace", in: "$SECRET", want: "$SECRET"},

		{name: "unset without default", in: "${MISSING}", wantErr: "referenced variable is unset"},
		{name: "unterminated", in: "${SECRET", wantErr: "unterminated"},
		{name: "empty reference", in: "${}", wantErr: "empty ${} reference"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newExpander(env).expand(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expand(%q) = %q, want error", tt.in, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expand(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("expand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandUnsetVariableIsDetectable(t *testing.T) {
	t.Parallel()

	_, err := newExpander(nil).expand("${MISSING}")
	if !errors.Is(err, ErrUnsetVariable) {
		t.Errorf("expand = %v, want ErrUnsetVariable", err)
	}
	if !strings.Contains(err.Error(), "MISSING") {
		t.Errorf("error should name the variable, got %q", err)
	}
}

func TestExpandFileReference(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	secretPath := filepath.Join(dir, "client-secret")
	// Mounted secrets routinely carry a trailing newline.
	if err := os.WriteFile(secretPath, []byte("  s3cret-from-file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := newExpander(nil).expand("${file:" + secretPath + "}")
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if got != "s3cret-from-file" {
		t.Errorf("expand = %q, want the trimmed file contents", got)
	}
}

func TestExpandFileReferenceErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty path", "${file:}", "empty path"},
		{"empty path with spaces", "${file:   }", "empty path"},
		{"relative path", "${file:relative/secret}", "must be an absolute path"},
		{"missing file", "${file:" + filepath.Join(dir, "nope") + "}", "reading"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := newExpander(nil).expand(tt.in)
			if err == nil {
				t.Fatalf("expand(%q) = nil error, want error", tt.in)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestExpandFileReferenceRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxFileSecretSize+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := newExpander(nil).expand("${file:" + big + "}")
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("expand of an oversized file = %v, want a size error", err)
	}
}

func TestExpandLeavesCommentsAlone(t *testing.T) {
	t.Parallel()

	env := map[string]string{"SET": "value"}

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// Documenting the syntax in a comment must not make startup fail.
			name: "unset variable in a full-line comment",
			in:   "# use ${MISSING} for the secret\nkey: ${SET}",
			want: "# use ${MISSING} for the secret\nkey: value",
		},
		{
			name: "trailing comment",
			in:   "key: ${SET} # or ${MISSING}",
			want: "key: value # or ${MISSING}",
		},
		{
			name: "a comment ends at the newline",
			in:   "# ${MISSING}\nkey: ${SET}",
			want: "# ${MISSING}\nkey: value",
		},
		{
			// YAML only starts a comment after whitespace, so this '#' is data.
			name: "hash inside a scalar is not a comment",
			in:   "key: a#${SET}",
			want: "key: a#value",
		},
		{
			name: "hash inside a quoted scalar is not a comment",
			in:   `key: "a # ${SET}"`,
			want: `key: "a # value"`,
		},
		{
			name: "references inside quotes still expand",
			in:   `key: "${SET}"`,
			want: `key: "value"`,
		},
		{
			name: "single quoted scalar with an escaped quote",
			in:   "key: 'it''s ${SET}'",
			want: "key: 'it''s value'",
		},
		{
			name: "escaped quote inside a double quoted scalar",
			in:   `key: "say \"${SET}\""`,
			want: `key: "say \"value\""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newExpander(env).expand(tt.in)
			if err != nil {
				t.Fatalf("expand(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("expand(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandUsesProcessEnvironment(t *testing.T) {
	// Not parallel: mutates the process environment.
	t.Setenv("SMTP_AUTH_PROXY_TEST_VAR", "from-env")

	got, err := Expand("value: ${SMTP_AUTH_PROXY_TEST_VAR}")
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if got != "value: from-env" {
		t.Errorf("Expand = %q", got)
	}
}

func TestExpandDoesNotLeakSecretsIntoErrors(t *testing.T) {
	t.Parallel()

	// The error for an unset variable names the variable, never a value that
	// happened to be resolved earlier in the same document.
	env := map[string]string{"KNOWN": "super-secret-value"}
	_, err := newExpander(env).expand("${KNOWN} ${MISSING}")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Errorf("error leaked a resolved secret: %q", err)
	}
}

func ExampleExpand() {
	os.Setenv("EXAMPLE_HOST", "smtp.example.com")
	defer os.Unsetenv("EXAMPLE_HOST")

	out, _ := Expand("host: ${EXAMPLE_HOST}\nport: ${EXAMPLE_PORT:-587}")
	fmt.Println(out)
	// Output:
	// host: smtp.example.com
	// port: 587
}
