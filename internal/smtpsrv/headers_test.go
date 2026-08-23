package smtpsrv

import (
	"errors"
	"strings"
	"testing"
)

const sampleMessage = "From: Printer <printer@lan.local>\r\n" +
	"To: ops@example.com\r\n" +
	"Subject: Scan complete\r\n" +
	"Message-ID: <abc@lan.local>\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"A scan finished.\r\n"

func TestParseMessage(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if got := m.Get("Subject"); got != "Scan complete" {
		t.Errorf("Subject = %q", got)
	}
	if got := m.Get("from"); got != "Printer <printer@lan.local>" {
		t.Errorf("From = %q (lookup must be case-insensitive)", got)
	}
	if got := string(m.Body()); got != "A scan finished.\r\n" {
		t.Errorf("Body = %q", got)
	}
}

func TestParseMessageAcceptsBareLF(t *testing.T) {
	t.Parallel()

	// Plenty of devices send bare LF. Rejecting them would break exactly the
	// hardware this proxy exists to keep working.
	raw := "From: a@example.com\nSubject: hi\n\nbody\n"
	m, err := parseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parseMessage with bare LF: %v", err)
	}
	if m.Get("Subject") != "hi" {
		t.Errorf("Subject = %q", m.Get("Subject"))
	}
	if string(m.Body()) != "body\n" {
		t.Errorf("Body = %q", m.Body())
	}
}

func TestParseMessageErrors(t *testing.T) {
	t.Parallel()

	if _, err := parseMessage([]byte("From: a@example.com\r\nno blank line")); !errors.Is(err, ErrNoHeaderSeparator) {
		t.Errorf("parseMessage without a blank line = %v, want ErrNoHeaderSeparator", err)
	}

	huge := strings.Repeat("X-Filler: "+strings.Repeat("a", 200)+"\r\n", 6000) + "\r\nbody"
	if _, err := parseMessage([]byte(huge)); !errors.Is(err, ErrHeaderTooLarge) {
		t.Errorf("parseMessage with oversized headers = %v, want ErrHeaderTooLarge", err)
	}
}

func TestRewriteHeadersReplacesAField(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}

	out := string(m.rewriteHeaders([]headerEdit{
		{Key: "From", Value: "sales@example.com"},
		{Key: "Reply-To", Value: "Printer <printer@lan.local>"},
	}))

	if strings.Contains(out, "printer@lan.local>\r\nTo:") {
		t.Error("the original From survived")
	}
	if !strings.Contains(out, "From: sales@example.com\r\n") {
		t.Errorf("From was not replaced:\n%s", out)
	}
	if !strings.Contains(out, "Reply-To: Printer <printer@lan.local>\r\n") {
		t.Errorf("Reply-To was not added:\n%s", out)
	}
	// Everything else must be untouched, byte for byte.
	for _, want := range []string{
		"To: ops@example.com\r\n",
		"Subject: Scan complete\r\n",
		"Message-ID: <abc@lan.local>\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lost header %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\r\n\r\nA scan finished.\r\n") {
		t.Errorf("body was altered:\n%q", out)
	}
}

func TestRewriteHeadersPrepends(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}

	out := string(m.rewriteHeaders([]headerEdit{
		{Key: "Received", Value: "from lan by proxy; Mon, 1 Jan 2026 00:00:00 +0000", Prepend: true},
	}))
	if !strings.HasPrefix(out, "Received: from lan by proxy") {
		t.Errorf("Received was not put at the top:\n%s", out)
	}
}

func TestRewriteHeadersDeletes(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}

	out := string(m.rewriteHeaders([]headerEdit{{Key: "Message-ID", Value: ""}}))
	if strings.Contains(out, "Message-ID") {
		t.Errorf("Message-ID was not deleted:\n%s", out)
	}
	if !strings.Contains(out, "Subject: Scan complete") {
		t.Error("deleting one field removed another")
	}
}

func TestRewriteHeadersPreservesFoldedValues(t *testing.T) {
	t.Parallel()

	raw := "From: a@example.com\r\n" +
		"Subject: a very long subject that has been\r\n" +
		"\tfolded across two lines\r\n" +
		"To: b@example.com\r\n" +
		"\r\n" +
		"body\r\n"

	m, err := parseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	out := string(m.rewriteHeaders([]headerEdit{{Key: "From", Value: "c@example.com"}}))

	if !strings.Contains(out, "\tfolded across two lines\r\n") {
		t.Errorf("a folded continuation line was lost:\n%s", out)
	}
	if !strings.Contains(out, "To: b@example.com\r\n") {
		t.Errorf("a header after the folded one was lost:\n%s", out)
	}
}

func TestRewriteHeadersDropsContinuationsOfAReplacedField(t *testing.T) {
	t.Parallel()

	// If a replaced field was folded, its continuation lines must go with it —
	// otherwise they would be left behind as a syntactically broken header.
	raw := "From: Some Very Long Name\r\n" +
		" <printer@lan.local>\r\n" +
		"To: b@example.com\r\n" +
		"\r\n" +
		"body\r\n"

	m, err := parseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	out := string(m.rewriteHeaders([]headerEdit{{Key: "From", Value: "sales@example.com"}}))

	if strings.Contains(out, "printer@lan.local") {
		t.Errorf("the continuation of the replaced field survived:\n%s", out)
	}
	if !strings.Contains(out, "From: sales@example.com\r\n") || !strings.Contains(out, "To: b@example.com\r\n") {
		t.Errorf("rewrite mangled the block:\n%s", out)
	}
}

// A header value carrying CRLF would otherwise become extra headers of the
// sender's choosing — a Bcc to an address the operator never approved.
func TestRewriteHeadersPreventsInjection(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}

	injected := "sales@example.com\r\nBcc: attacker@evil.example"
	out := string(m.rewriteHeaders([]headerEdit{{Key: "From", Value: injected}}))

	// The value must survive only as text inside From, never as its own field.
	for _, line := range strings.Split(out, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Errorf("header injection succeeded; %q became a real field:\n%s", line, out)
		}
	}
	if !strings.Contains(out, "From: sales@example.com Bcc: attacker@evil.example\r\n") {
		t.Errorf("the value was not folded into one line:\n%s", out)
	}
}

func TestSanitizeHeaderValue(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"plain":                  "plain",
		"a\r\nb":                 "a b",
		"a\nb":                   "a b",
		"a\rb":                   "a b",
		"\r\nleading":            "leading",
		"trailing\r\n":           "trailing",
		"multi\r\nline\r\nvalue": "multi line value",
	}
	for in, want := range tests {
		if got := sanitizeHeaderValue(in); got != want {
			t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRewriteHeadersAddsAMissingField(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	out := string(m.rewriteHeaders([]headerEdit{{Key: "X-Original-From", Value: "printer@lan.local"}}))
	if !strings.Contains(out, "X-Original-From: printer@lan.local\r\n") {
		t.Errorf("a new header was not added:\n%s", out)
	}
}

func TestRewriteHeadersWithNoEditsIsANoOp(t *testing.T) {
	t.Parallel()

	m, err := parseMessage([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if got := string(m.rewriteHeaders(nil)); got != sampleMessage {
		t.Errorf("rewriting with no edits changed the message:\n%q", got)
	}
}
