package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/legal"
)

func TestLicensesNeedsNoConfiguration(t *testing.T) {
	t.Chdir(t.TempDir())
	file, err := os.Create(filepath.Join(t.TempDir(), "notices.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := run(t.Context(), []string{"licenses"}, file, file); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file.Name())
	if err != nil || string(got) != legal.Notices {
		t.Fatalf("notice mismatch: %v", err)
	}
}
