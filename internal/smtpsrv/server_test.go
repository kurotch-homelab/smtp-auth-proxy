package smtpsrv

import (
	"errors"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

const testBody = "From: sales@example.com\r\n" +
	"To: ops@example.net\r\n" +
	"Subject: Scan complete\r\n" +
	"\r\n" +
	"A scan finished.\r\n"

func TestSubmissionEndToEnd(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, true)

	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
	if err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody); err != nil {
		t.Fatalf("submission: %v", err)
	}

	sub := h.submitter.last()
	if sub == nil {
		t.Fatal("nothing reached the submitter")
	}
	if sub.Mailbox.Address != "sales@example.com" {
		t.Errorf("Mailbox = %q", sub.Mailbox.Address)
	}
	if len(sub.Recipients) != 1 || sub.Recipients[0] != "ops@example.net" {
		t.Errorf("Recipients = %v", sub.Recipients)
	}
	if !sub.TLS {
		t.Error("TLS was not recorded on a STARTTLS connection")
	}
	// The proxy must stamp its own trace header.
	if !strings.HasPrefix(string(sub.Raw), "Received: ") {
		t.Errorf("no Received header was added:\n%s", firstLines(string(sub.Raw), 3))
	}
	if !strings.Contains(string(sub.Raw), "A scan finished.") {
		t.Error("the body did not survive")
	}
}

func TestAuthLoginIsSupported(t *testing.T) {
	t.Parallel()

	// AUTH LOGIN is not a standard SASL mechanism, but a lot of printer
	// firmware supports nothing else.
	h := startServer(t, nil)
	c := h.dial(t, true)

	if !c.SupportsAuth(sasl.Login) {
		t.Fatal("the server does not advertise AUTH LOGIN")
	}
	if err := c.Auth(sasl.NewLoginClient("svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH LOGIN: %v", err)
	}
	if err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody); err != nil {
		t.Fatalf("submission after AUTH LOGIN: %v", err)
	}
	if h.submitter.count() != 1 {
		t.Errorf("submitter saw %d messages, want 1", h.submitter.count())
	}
}

func TestAuthFailuresAreIndistinguishable(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)

	// An unknown username and a wrong password must produce the same response,
	// or the server becomes a username oracle.
	var responses []string
	for _, creds := range [][2]string{{"svc-printer", "wrong"}, {"does-not-exist", "wrong"}} {
		c := h.dial(t, true)
		err := c.Auth(sasl.NewPlainClient("", creds[0], creds[1]))
		if err == nil {
			t.Fatalf("AUTH with %v succeeded", creds)
		}
		responses = append(responses, err.Error())
	}

	if responses[0] != responses[1] {
		t.Errorf("the server distinguishes a bad password from a bad username:\n  %q\n  %q",
			responses[0], responses[1])
	}
	if len(h.auth.attempts()) != 2 {
		t.Errorf("the authenticator saw %d attempts, want 2", len(h.auth.attempts()))
	}
}

func TestAuthIsNotOfferedWithoutTLS(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, false)

	// PLAIN and LOGIN both send the password in the clear, so the server must
	// not advertise them before the connection is encrypted.
	if c.SupportsAuth(sasl.Plain) || c.SupportsAuth(sasl.Login) {
		t.Error("AUTH is advertised on an unencrypted connection")
	}

	err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret"))
	if err == nil {
		t.Fatal("AUTH succeeded on an unencrypted connection")
	}
	if len(h.auth.attempts()) != 0 {
		t.Error("credentials reached the authenticator over an unencrypted connection")
	}
}

func TestAllowInsecureAuthOptsOut(t *testing.T) {
	t.Parallel()

	// The escape hatch for devices with no TLS support at all.
	h := startServer(t, func(o *Options) {
		o.AllowInsecureAuth = true
		o.Listeners = []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSStartTLS, RequireAuth: true}}
	})
	c := h.dial(t, false)

	if !c.SupportsAuth(sasl.Plain) {
		t.Fatal("AUTH PLAIN is not advertised even though allow_insecure_auth is set")
	}
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH PLAIN over plaintext: %v", err)
	}
}

func TestUnauthenticatedSubmissionIsRefused(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, true)

	// There is no open-relay mode; MAIL FROM before AUTH must fail.
	err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody)
	if err == nil {
		t.Fatal("an unauthenticated submission was accepted")
	}
	if code := smtpCode(err); code != 530 {
		t.Errorf("status = %d, want 530", code)
	}
	if h.submitter.count() != 0 {
		t.Error("an unauthenticated message reached the submitter")
	}
}

func TestSenderPolicyIsEnforcedOverTheWire(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	// The account may only send as sales@example.com.
	impersonation := "From: ceo@example.com\r\nTo: ops@example.net\r\n\r\nhello\r\n"
	err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, impersonation)
	if err == nil {
		t.Fatal("a message impersonating another sender was accepted")
	}
	if code := smtpCode(err); code != 550 {
		t.Errorf("status = %d, want 550", code)
	}
	if !strings.Contains(err.Error(), "may not send as") {
		t.Errorf("the rejection does not say why: %v", err)
	}
	if h.submitter.count() != 0 {
		t.Error("a rejected message reached the submitter")
	}
}

func TestRewritePolicyReplacesTheSender(t *testing.T) {
	t.Parallel()

	h := startServer(t, func(o *Options) {
		auth, ok := o.Auth.(*fakeAuth)
		if !ok {
			t.Fatalf("Auth is %T, want *fakeAuth", o.Auth)
		}
		auth.identity = testIdentity(store.FromPolicyRewrite)
	})
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	body := "From: Printer <printer@lan.local>\r\nTo: ops@example.net\r\n\r\nhello\r\n"
	if err := h.sendMessage(t, c, "printer@lan.local", []string{"ops@example.net"}, body); err != nil {
		t.Fatalf("submission: %v", err)
	}

	sub := h.submitter.last()
	raw := string(sub.Raw)
	if !strings.Contains(raw, "From: sales@example.com\r\n") {
		t.Errorf("From was not rewritten:\n%s", firstLines(raw, 6))
	}
	// A reply must still reach the device that sent the message.
	if !strings.Contains(raw, "Reply-To: \"Printer\" <printer@lan.local>") &&
		!strings.Contains(raw, "Reply-To: Printer <printer@lan.local>") {
		t.Errorf("Reply-To does not preserve the original sender:\n%s", firstLines(raw, 6))
	}
	if !strings.Contains(raw, "X-Original-From:") {
		t.Errorf("X-Original-From is missing:\n%s", firstLines(raw, 6))
	}
	if sub.HeaderFrom.Normalized != "sales@example.com" {
		t.Errorf("HeaderFrom = %q, want the rewritten address", sub.HeaderFrom.Normalized)
	}
}

func TestOversizedMessageIsRefused(t *testing.T) {
	t.Parallel()

	h := startServer(t, func(o *Options) { o.MaxMessageBytes = 2048 })
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	big := "From: sales@example.com\r\nTo: ops@example.net\r\n\r\n" + strings.Repeat("x", 8192)
	err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, big)
	if err == nil {
		t.Fatal("an oversized message was accepted")
	}
	if h.submitter.count() != 0 {
		t.Error("an oversized message reached the submitter")
	}
}

func TestTooManyRecipients(t *testing.T) {
	t.Parallel()

	h := startServer(t, func(o *Options) { o.MaxRecipients = 2 })
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	if err := c.Mail("sales@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	for i, rcpt := range []string{"a@example.net", "b@example.net", "c@example.net"} {
		err := c.Rcpt(rcpt, nil)
		if i < 2 && err != nil {
			t.Fatalf("RCPT %d: %v", i, err)
		}
		if i == 2 && err == nil {
			t.Fatal("a recipient past the limit was accepted")
		}
	}
}

func TestMalformedAddressesAreRefused(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	if err := c.Mail("not-an-address", nil); err == nil {
		t.Error("a malformed MAIL FROM was accepted")
	}
	if err := c.Mail("sales@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("also-not-an-address", nil); err == nil {
		t.Error("a malformed RCPT TO was accepted")
	}
}

func TestMessageWithoutHeadersIsRefused(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, "just some text with no header block")
	if err == nil {
		t.Fatal("a message with no header block was accepted")
	}
	if code := smtpCode(err); code != 550 {
		t.Errorf("status = %d, want 550", code)
	}
}

func TestQueueFailureAsksTheClientToRetry(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	h.submitter.err = errors.New("database is down")

	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody)
	if err == nil {
		t.Fatal("the submission succeeded even though queueing failed")
	}
	// The message was fine and the failure is ours, so the client should retry.
	if code := smtpCode(err); code < 400 || code >= 500 {
		t.Errorf("status = %d, want a 4xx so the client retries", code)
	}
	// The client must not be told what broke internally.
	if strings.Contains(err.Error(), "database is down") {
		t.Errorf("the internal error leaked to the client: %v", err)
	}
}

func TestSubjectIsOnlyRecordedWhenEnabled(t *testing.T) {
	t.Parallel()

	// Subjects can carry personal data, so they stay out of the queue by
	// default.
	off := startServer(t, nil)
	c := off.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := off.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if got := off.submitter.last().Subject; got != "" {
		t.Errorf("Subject = %q, want it withheld by default", got)
	}

	on := startServer(t, func(o *Options) { o.RecordSubjects = true })
	c2 := on.dial(t, true)
	if err := c2.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	if err := on.sendMessage(t, c2, "sales@example.com", []string{"ops@example.net"}, testBody); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if got := on.submitter.last().Subject; got != "Scan complete" {
		t.Errorf("Subject = %q, want it recorded when enabled", got)
	}
}

func TestResetClearsTheEnvelopeButKeepsAuth(t *testing.T) {
	t.Parallel()

	h := startServer(t, nil)
	c := h.dial(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	if err := c.Mail("sales@example.com", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := c.Rcpt("ops@example.net", nil); err != nil {
		t.Fatalf("RCPT TO: %v", err)
	}
	if err := c.Reset(); err != nil {
		t.Fatalf("RSET: %v", err)
	}

	// RSET must not log the session out; a second message on the same
	// connection should still work.
	if err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody); err != nil {
		t.Fatalf("submission after RSET: %v", err)
	}
	if h.submitter.count() != 1 {
		t.Errorf("submitter saw %d messages, want 1", h.submitter.count())
	}
}

func TestConnectionIsClosedAfterRepeatedAuthFailures(t *testing.T) {
	t.Parallel()

	h := startServer(t, func(o *Options) { o.MaxAuthFailures = 2 })
	c := h.dial(t, true)

	for range 2 {
		if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "wrong")); err == nil {
			t.Fatal("a wrong password was accepted")
		}
	}

	// The connection should now be gone, so guessing costs a fresh TCP and TLS
	// handshake per attempt rather than one socket forever.
	if err := c.Noop(); err == nil {
		t.Error("the connection survived repeated authentication failures")
	}
}

func TestServeRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	base := func() Options {
		return Options{
			Hostname:  "proxy.test",
			Listeners: []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSNone, RequireAuth: true}},
			Auth:      &fakeAuth{},
			Submitter: &fakeSubmitter{},
		}
	}

	tests := map[string]func(*Options){
		"no authenticator": func(o *Options) { o.Auth = nil },
		"no submitter":     func(o *Options) { o.Submitter = nil },
		"no listeners":     func(o *Options) { o.Listeners = nil },
		"TLS listener without a certificate": func(o *Options) {
			o.Listeners = []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSStartTLS, RequireAuth: true}}
			o.TLSConfig = nil
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := base()
			mutate(&opts)
			if _, err := New(opts); err == nil {
				t.Error("New accepted invalid options")
			}
		})
	}
}

func TestImplicitTLSListener(t *testing.T) {
	t.Parallel()

	// Port 465 style: the client speaks TLS from the first byte.
	h := startServer(t, func(o *Options) {
		o.Listeners = []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSImplicit, RequireTLS: true, RequireAuth: true}}
	})

	c, err := smtp.DialTLS(h.addr, h.tlsConfig)
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(sasl.NewPlainClient("", "svc-printer", "s3cret")); err != nil {
		t.Fatalf("AUTH over implicit TLS: %v", err)
	}
	if err := h.sendMessage(t, c, "sales@example.com", []string{"ops@example.net"}, testBody); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if !h.submitter.last().TLS {
		t.Error("TLS was not recorded on an implicit TLS connection")
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\r\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
