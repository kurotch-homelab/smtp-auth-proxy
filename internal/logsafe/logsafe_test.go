package logsafe_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/logsafe"
)

func TestStringNeutralizesLogForging(t *testing.T) {
	t.Parallel()

	// The canonical attack: a username that fakes a second log line.
	forged := "alice\ntime=2026-01-01T00:00:00Z level=INFO msg=\"admin sign-in succeeded\""
	got := logsafe.String(forged)

	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("a newline survived: %q", got)
	}
	// The evidence stays visible rather than silently vanishing.
	if !strings.Contains(got, `\n`) {
		t.Errorf("the injection attempt is no longer visible: %q", got)
	}
	if !strings.Contains(got, "alice") {
		t.Errorf("the legitimate part was lost: %q", got)
	}
}

func TestStringHandlesEveryControlCharacter(t *testing.T) {
	t.Parallel()

	var in strings.Builder
	in.WriteString("user")
	for c := rune(0); c < 0x20; c++ {
		in.WriteRune(c)
	}
	in.WriteRune(0x7f)
	in.WriteString("name")

	got := logsafe.String(in.String())
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("a control character %q survived: %q", r, got)
		}
	}
	if !strings.HasPrefix(got, "user") || !strings.HasSuffix(got, "name") {
		t.Errorf("the printable parts were damaged: %q", got)
	}
}

func TestStringLeavesNormalValuesAlone(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"svc-printer",
		"/api/v1/mailboxes/01a02f15",
		"sales@example.com",
		"日本語のユーザー名",
		"",
	} {
		if got := logsafe.String(s); got != s {
			t.Errorf("String(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestStringBoundsTheLength(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("x", 10_000)
	got := logsafe.String(huge)
	if len(got) > 1024 {
		t.Errorf("an attacker-sized value stayed %d bytes long", len(got))
	}
	if !strings.HasSuffix(got, "(truncated)") {
		t.Errorf("truncation is not visible: %q", got[len(got)-30:])
	}
}

func TestError(t *testing.T) {
	t.Parallel()

	if got := logsafe.Error(nil); got != "" {
		t.Errorf("Error(nil) = %q, want empty", got)
	}

	// Error text routinely embeds user input.
	err := fmt.Errorf("no account named %q", "evil\nuser")
	if got := logsafe.Error(err); strings.Contains(got, "\n") {
		t.Errorf("a newline survived through an error: %q", got)
	}
	if got := logsafe.Error(errors.New("plain")); got != "plain" {
		t.Errorf("Error = %q, want plain", got)
	}
}
