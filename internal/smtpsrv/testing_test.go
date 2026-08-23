package smtpsrv

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// fakeAuth answers from a fixed table of credentials.
type fakeAuth struct {
	mu sync.Mutex
	// credentials maps username to password.
	credentials map[string]string
	identity    *Identity
	// calls records every attempt, so tests can assert the server does not leak
	// which part of a credential was wrong.
	calls []string
	err   error
}

func (f *fakeAuth) Authenticate(_ context.Context, username, password string, _ net.IP) (*Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, username)
	if f.err != nil {
		return nil, f.err
	}
	if want, ok := f.credentials[username]; !ok || want != password {
		return nil, ErrAuthFailed
	}

	id := *f.identity
	id.Username = username
	return &id, nil
}

func (f *fakeAuth) attempts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeSubmitter records what the session decided to queue.
type fakeSubmitter struct {
	mu       sync.Mutex
	received []*Submission
	err      error
}

func (f *fakeSubmitter) Submit(_ context.Context, sub *Submission) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return "", f.err
	}
	f.received = append(f.received, sub)
	return "msg-1", nil
}

func (f *fakeSubmitter) last() *Submission {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.received) == 0 {
		return nil
	}
	return f.received[len(f.received)-1]
}

func (f *fakeSubmitter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.received)
}

// testMailbox is the mailbox every fixture account may send as.
func testMailbox() *store.Mailbox {
	return &store.Mailbox{
		ID: "mb-1", Address: "sales@example.com", Enabled: true, Transport: store.TransportSMTP,
	}
}

func testIdentity(fromPolicy store.FromPolicy) *Identity {
	return &Identity{
		AccountID: "acct-1",
		Username:  "svc-printer",
		Account: policy.Account{
			ID: "acct-1", Username: "svc-printer", Enabled: true, Policy: fromPolicy,
		},
		Mailboxes: []*store.Mailbox{testMailbox()},
	}
}

// harness is a running server plus the fakes behind it.
type harness struct {
	server    *Server
	auth      *fakeAuth
	submitter *fakeSubmitter
	addr      string
	tlsConfig *tls.Config
}

// startServer brings up a server on an ephemeral port and tears it down with
// the test.
func startServer(t *testing.T, mutate func(*Options)) *harness {
	t.Helper()

	tlsConfig, err := BuildTLSConfig(config.TLS{SelfSigned: true, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}

	auth := &fakeAuth{
		credentials: map[string]string{"svc-printer": "s3cret"},
		identity:    testIdentity(store.FromPolicyReject),
	}
	submitter := &fakeSubmitter{}

	opts := Options{
		Hostname:            "proxy.test",
		Listeners:           []config.Listener{{Address: "127.0.0.1:0", TLS: config.TLSStartTLS, RequireTLS: true, RequireAuth: true}},
		TLSConfig:           tlsConfig,
		MaxMessageBytes:     1 << 20,
		MaxRecipients:       10,
		MaxConnections:      50,
		MaxConnectionsPerIP: 10,
		MaxAuthFailures:     3,
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		Auth:                auth,
		Submitter:           submitter,
		Log:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&opts)
	}

	srv, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()

	select {
	case <-srv.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("the server never finished binding")
	}

	addrs := srv.Addresses()
	if len(addrs) == 0 {
		t.Fatal("the server never reported a listening address")
	}
	addr := addrs[0]

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after Shutdown")
		}
	})

	return &harness{
		server:    srv,
		auth:      auth,
		submitter: submitter,
		addr:      addr,
		// The server generates a self-signed certificate for the test, so
		// verification is deliberately skipped here.
		tlsConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	}
}

// dial connects a client, completing STARTTLS unless plaintext is requested.
func (h *harness) dial(t *testing.T, startTLS bool) *smtp.Client {
	t.Helper()

	var (
		c   *smtp.Client
		err error
	)
	if startTLS {
		c, err = smtp.DialStartTLS(h.addr, h.tlsConfig)
	} else {
		c, err = smtp.Dial(h.addr)
	}
	if err != nil {
		t.Fatalf("dialing %s (startTLS=%v): %v", h.addr, startTLS, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// sendMessage runs a full submission and returns the server's error, if any.
func (h *harness) sendMessage(t *testing.T, c *smtp.Client, from string, to []string, body string) error {
	t.Helper()

	if err := c.Mail(from, nil); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	return w.Close()
}

// smtpCode extracts the numeric status from a server error.
func smtpCode(err error) int {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Code
	}
	return 0
}
