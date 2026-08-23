package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenkeyProducesAUsableKey(t *testing.T) {
	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"genkey", "-quiet"}, w, w)
	})
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	spec := strings.TrimSpace(out)
	if !strings.HasPrefix(spec, "k1:") {
		t.Fatalf("genkey printed %q, want an id-prefixed key", spec)
	}

	// The generated key has to be one the configuration loader accepts, or the
	// command is worse than useless.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	doc := "encryption:\n  keys: [\"" + spec + "\"]\nsmtp:\n  tls:\n    self_signed: true\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing the config: %v", err)
	}

	if _, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"serve", "--config", path, "--check"}, w, w)
	}); err != nil {
		t.Errorf("a configuration using the generated key did not validate: %v", err)
	}
}

func TestGenkeyExplainsWhatToDoWithTheKey(t *testing.T) {
	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"genkey"}, w, w)
	})
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	// An operator has to know this key is not recoverable and not shareable.
	for _, want := range []string{"cannot be recovered", "SMTP_AUTH_PROXY_ENCRYPTION_KEY", "rotate"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not mention %q:\n%s", want, out)
		}
	}
}

func TestGenkeyRejectsABadIdentifier(t *testing.T) {
	_, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"genkey", "-id", "a:b"}, w, w)
	})
	if err == nil {
		t.Error("genkey accepted an identifier containing a separator")
	}
}

func TestPasswdGeneratesAndHashes(t *testing.T) {
	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"passwd"}, w, w)
	})
	if err != nil {
		t.Fatalf("passwd: %v", err)
	}
	if !strings.Contains(out, "password: ") {
		t.Errorf("a generated password was not printed:\n%s", out)
	}
	if !strings.Contains(out, "hash:     $argon2id$") {
		t.Errorf("the hash is not a PHC argon2id string:\n%s", out)
	}
}

func TestPasswdHashesAGivenPassword(t *testing.T) {
	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"passwd", "-password", "chosen-by-hand"}, w, w)
	})
	if err != nil {
		t.Fatalf("passwd: %v", err)
	}
	// The password was supplied, so echoing it back would only risk it landing
	// in a shell history or a screenshot.
	if strings.Contains(out, "chosen-by-hand") {
		t.Errorf("the supplied password was echoed back:\n%s", out)
	}
	if !strings.Contains(out, "$argon2id$") {
		t.Errorf("no hash was printed:\n%s", out)
	}
}

func TestServeCheckReportsAnInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("log:\n  level: nonsense\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	_, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"serve", "--config", path, "--check"}, w, w)
	})
	if err == nil {
		t.Error("--check accepted an invalid configuration")
	}
}

func TestServeCheckSurfacesWarnings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	doc := "encryption:\n  keys: [\"k1:0000000000000000000000000000000000000000000=\"]\n" +
		"smtp:\n  allow_insecure_auth: true\n  tls:\n    self_signed: true\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"serve", "--config", path, "--check"}, w, w)
	})
	if err != nil {
		t.Fatalf("--check: %v", err)
	}
	// A configuration that sends passwords in the clear is legal but must be
	// said out loud.
	if !strings.Contains(out, "plaintext") {
		t.Errorf("--check did not warn about plaintext authentication:\n%s", out)
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"debug":   "DEBUG",
		"info":    "INFO",
		"warn":    "WARN",
		"warning": "WARN",
		"error":   "ERROR",
		"ERROR":   "ERROR",
		"":        "INFO",
		"unknown": "INFO",
	}
	for in, want := range tests {
		if got := parseLevel(in).String(); got != want {
			t.Errorf("parseLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHealthcheckProbesTheEndpoint(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()

	if _, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"healthcheck", "--url", healthy.URL}, w, w)
	}); err != nil {
		t.Errorf("healthcheck against a healthy endpoint: %v", err)
	}

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()

	if _, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"healthcheck", "--url", unhealthy.URL}, w, w)
	}); err == nil {
		t.Error("healthcheck against an unhealthy endpoint reported success")
	}

	// Nothing listening at all.
	if _, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"healthcheck", "--url", "http://127.0.0.1:1/readyz", "--timeout", "1s"}, w, w)
	}); err == nil {
		t.Error("healthcheck against a closed port reported success")
	}
}
