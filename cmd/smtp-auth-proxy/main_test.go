package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects a pipe into the *os.File the CLI writes to and
// returns what was written.
func captureStdout(t *testing.T, fn func(w *os.File) error) (string, error) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	runErr := fn(w)
	w.Close()

	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, readErr := r.Read(buf)
		sb.Write(buf[:n])
		if readErr != nil {
			break
		}
	}
	r.Close()
	return sb.String(), runErr
}

func TestRunVersionPrintsBuildInfo(t *testing.T) {
	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"version"}, w, w)
	})
	if err != nil {
		t.Fatalf("run(version) = %v", err)
	}
	if !strings.Contains(out, "commit") {
		t.Errorf("version output missing build metadata: %q", out)
	}
}

func TestRunHelpListsEverySubcommand(t *testing.T) {
	out, err := captureStdout(t, func(w *os.File) error {
		return run(context.Background(), []string{"--help"}, w, w)
	})
	if err != nil {
		t.Fatalf("run(--help) = %v", err)
	}
	for _, c := range commands() {
		if !strings.Contains(out, c.name) {
			t.Errorf("help output does not mention subcommand %q:\n%s", c.name, out)
		}
	}
}

func TestRunRejectsUnknownAndMissingSubcommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", nil, "no subcommand"},
		{"unknown subcommand", []string{"frobnicate"}, `unknown subcommand "frobnicate"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := captureStdout(t, func(w *os.File) error {
				return run(context.Background(), tt.args, w, w)
			})
			if err == nil {
				t.Fatalf("run(%v) = nil, want error", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("run(%v) error = %q, want it to contain %q", tt.args, err, tt.want)
			}
		})
	}
}
