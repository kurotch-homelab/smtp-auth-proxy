//go:build e2e

// Package app's end-to-end test drives the whole proxy the way a LAN device
// would: connect, STARTTLS, AUTH, send — and assert the message arrives at a
// stand-in for Exchange Online with the right identity attached.
//
// It is behind the e2e build tag because it starts real listeners.
package app_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/app"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/fakeexchange"
)

const (
	testTenant    = "11111111-1111-1111-1111-111111111111"
	testClientID  = "22222222-2222-2222-2222-222222222222"
	testSecret    = "the-client-secret"
	testAccessTok = "T0K3N"
	mailbox       = "sales@example.com"
	smtpUser      = "svc-printer"
	smtpPassword  = "device-password"
)

// environment is a proxy wired to fake upstreams.
type environment struct {
	proxyAddr string
	exchange  *fakeexchange.Server
	db        *store.DB
	tlsConfig *tls.Config
}

// setup builds the whole stack: a fake Entra, a fake Exchange, a seeded
// database and a running proxy.
func setup(t *testing.T) *environment {
	t.Helper()

	cert := selfSigned(t)
	caPath := writeCertPEM(t, cert)

	entra := startFakeEntra(t, cert)
	exchange := fakeexchange.Start(t, cert)

	dir := t.TempDir()
	keySpec := generateKey(t)

	cfg := config.Defaults()
	cfg.Log.Level = "error"
	cfg.Log.Format = "text"
	cfg.Encryption.Keys = []string{keySpec}
	cfg.Database.DSN = filepath.Join(dir, "proxy.db")
	cfg.SMTP.Hostname = "proxy.test"
	cfg.SMTP.Listeners = []config.Listener{
		{Address: "127.0.0.1:0", TLS: config.TLSStartTLS, RequireTLS: true, RequireAuth: true},
	}
	cfg.SMTP.TLS = config.TLS{SelfSigned: true, MinVersion: "1.2"}
	cfg.Upstream.SMTP.Host = exchange.Host()
	cfg.Upstream.SMTP.Port = exchange.Port()
	cfg.Upstream.OAuth.Authority = entra.URL
	cfg.Upstream.TLS.CAFile = caPath
	cfg.Queue.PollInterval = config.Duration(20 * time.Millisecond)
	// Delivery is paced to Exchange's real budget; the test sends one message.
	cfg.Queue.Retry.Backoff = []config.Duration{config.Duration(10 * time.Millisecond)}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("the test configuration is invalid:\n%v", err)
	}

	log := testLogger(t)
	proxy, err := app.New(t.Context(), cfg, log)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	seed(t, proxy.DB(), proxy.Keyring())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = proxy.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("the proxy did not shut down")
		}
	})

	addr := waitForListener(t, proxy)

	return &environment{
		proxyAddr: addr,
		exchange:  exchange,
		db:        proxy.DB(),
		// The proxy generates its own certificate for this test, so
		// verification is deliberately skipped.
		tlsConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

// waitForListener polls the app's SMTP address until it is bound.
func waitForListener(t *testing.T, proxy *app.App) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if addrs := proxy.SMTPAddresses(); len(addrs) > 0 {
			return addrs[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the proxy never reported a listening address")
	return ""
}

// seed creates the credential, mailbox and account a submission needs.
func seed(t *testing.T, db *store.DB, kr *appcrypto.Keyring) {
	t.Helper()

	cred := &store.OAuthCredential{
		Name: "primary", TenantID: testTenant, ClientID: testClientID,
		AuthType: store.AuthTypeSecret,
	}
	if err := db.Credentials().Create(t.Context(), cred); err != nil {
		t.Fatalf("creating the credential: %v", err)
	}
	sealed, err := kr.EncryptString(testSecret, cred.SecretContext())
	if err != nil {
		t.Fatalf("sealing the secret: %v", err)
	}
	cred.ClientSecretEnc = sealed
	if err := db.Credentials().Update(t.Context(), cred); err != nil {
		t.Fatalf("storing the sealed secret: %v", err)
	}

	mb := &store.Mailbox{
		Address: mailbox, DisplayName: "Sales", OAuthCredentialID: cred.ID,
		Transport: store.TransportSMTP, Enabled: true,
	}
	if err := db.Mailboxes().Create(t.Context(), mb); err != nil {
		t.Fatalf("creating the mailbox: %v", err)
	}

	hash, err := appcrypto.HashPassword(smtpPassword)
	if err != nil {
		t.Fatalf("hashing the account password: %v", err)
	}
	account := &store.SMTPAccount{
		Username: smtpUser, PasswordHash: hash, Description: "the office printer",
		DefaultMailboxID: store.NullString(mb.ID),
		FromPolicy:       store.FromPolicyReject, Enabled: true,
	}
	if err := db.Accounts().Create(t.Context(), account); err != nil {
		t.Fatalf("creating the SMTP account: %v", err)
	}
	if err := db.Accounts().SetMailboxes(t.Context(), account.ID, []string{mb.ID}); err != nil {
		t.Fatalf("linking the mailbox: %v", err)
	}
}

// TestSubmissionReachesExchange is the whole point of the proxy: a device that
// only speaks SMTP-AUTH with a password gets its mail delivered through OAuth.
func TestSubmissionReachesExchange(t *testing.T) {
	env := setup(t)

	c, err := smtp.DialStartTLS(env.proxyAddr, env.tlsConfig)
	if err != nil {
		t.Fatalf("connecting to the proxy: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(sasl.NewPlainClient("", smtpUser, smtpPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	body := "From: " + mailbox + "\r\n" +
		"To: ops@example.net\r\n" +
		"Subject: Scan complete\r\n" +
		"\r\n" +
		"A scan finished.\r\n"

	if err := c.SendMail(mailbox, []string{"ops@example.net"}, strings.NewReader(body)); err != nil {
		t.Fatalf("sending: %v", err)
	}

	// The proxy accepted the message and queued it; the workers deliver it.
	waitFor(t, "the message to reach Exchange", func() bool {
		return len(env.exchange.Deliveries()) == 1
	})

	d := env.exchange.Deliveries()[0]
	if d.AuthUser != mailbox {
		t.Errorf("XOAUTH2 user = %q, want the shared mailbox %q", d.AuthUser, mailbox)
	}
	if d.AuthToken != testAccessTok {
		t.Errorf("XOAUTH2 token = %q, want the one Entra issued", d.AuthToken)
	}
	// The exact bytes, separators included.
	want := "user=" + mailbox + "\x01auth=Bearer " + testAccessTok + "\x01\x01"
	if string(d.RawXOAuth2) != want {
		t.Errorf("XOAUTH2 =\n %q\nwant\n %q", d.RawXOAuth2, want)
	}
	if d.EnvelopeFrom != mailbox {
		t.Errorf("envelope sender = %q, want the mailbox", d.EnvelopeFrom)
	}
	if !strings.Contains(d.Data, "A scan finished.") {
		t.Errorf("the body did not survive:\n%s", d.Data)
	}
	// The proxy stamps its own trace header.
	if !strings.Contains(d.Data, "Received: from") || !strings.Contains(d.Data, "proxy.test") {
		t.Errorf("no Received header from the proxy:\n%s", d.Data)
	}

	waitFor(t, "the queue to record the delivery", func() bool {
		counts, err := env.db.Messages().CountByStatus(t.Context())
		return err == nil && counts[store.StatusSent] == 1
	})
}

func TestImpersonationIsRefusedBeforeItLeavesTheLAN(t *testing.T) {
	env := setup(t)

	c, err := smtp.DialStartTLS(env.proxyAddr, env.tlsConfig)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(sasl.NewPlainClient("", smtpUser, smtpPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}

	body := "From: ceo@example.com\r\nTo: ops@example.net\r\n\r\nplease wire funds\r\n"
	err = c.SendMail(mailbox, []string{"ops@example.net"}, strings.NewReader(body))
	if err == nil {
		t.Fatal("a message impersonating another sender was accepted")
	}

	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) && smtpErr.Code != 550 {
		t.Errorf("status = %d, want 550", smtpErr.Code)
	}
	// Nothing must reach Microsoft 365.
	time.Sleep(200 * time.Millisecond)
	if n := len(env.exchange.Deliveries()); n != 0 {
		t.Errorf("%d impersonated messages were delivered", n)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	env := setup(t)

	c, err := smtp.DialStartTLS(env.proxyAddr, env.tlsConfig)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(sasl.NewPlainClient("", smtpUser, "wrong")); err == nil {
		t.Fatal("a wrong password was accepted")
	}
}

func TestUpstreamRejectionIsRetried(t *testing.T) {
	env := setup(t)
	// Exchange throttles the first attempt, as it does for a mailbox over its
	// 30 messages/minute budget.
	env.exchange.SetBehavior(fakeexchange.Behavior{FailAfterDeliveries: 0, RejectData: "451 4.7.500 Server busy"})

	c, err := smtp.DialStartTLS(env.proxyAddr, env.tlsConfig)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Auth(sasl.NewPlainClient("", smtpUser, smtpPassword)); err != nil {
		t.Fatalf("AUTH: %v", err)
	}
	body := "From: " + mailbox + "\r\nTo: ops@example.net\r\n\r\nhello\r\n"
	if err := c.SendMail(mailbox, []string{"ops@example.net"}, strings.NewReader(body)); err != nil {
		t.Fatalf("sending: %v", err)
	}

	// The device already got its 250; the retry is the proxy's problem now.
	waitFor(t, "the message to be deferred", func() bool {
		counts, err := env.db.Messages().CountByStatus(t.Context())
		return err == nil && counts[store.StatusDeferred] > 0
	})

	// Once the upstream recovers, the queue drains without the device doing
	// anything.
	env.exchange.SetBehavior(fakeexchange.Behavior{})
	waitFor(t, "the message to be delivered after the upstream recovered", func() bool {
		return len(env.exchange.Deliveries()) == 1
	})
}

// testLogger writes the proxy's logs into the test output when -v is used, and
// discards them otherwise.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()

	if os.Getenv("E2E_LOG") == "" {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- fakes -----------------------------------------------------------------

// startFakeEntra serves the token endpoint MSAL needs.
func startFakeEntra(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	mux := http.NewServeMux()
	mux.HandleFunc("/{tenant}/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		writeJSON(w, map[string]any{
			"issuer":                 srv.URL + "/" + tenant + "/v2.0",
			"authorization_endpoint": srv.URL + "/" + tenant + "/oauth2/v2.0/authorize",
			"token_endpoint":         srv.URL + "/" + tenant + "/oauth2/v2.0/token",
		})
	})
	mux.HandleFunc("/{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.Form.Get("client_secret"); got != testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `{"error":"invalid_client","error_description":"got %q"}`, got)
			return
		}
		writeJSON(w, map[string]any{
			"token_type":   "Bearer",
			"expires_in":   3599,
			"access_token": testAccessTok,
		})
	})

	srv = httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// selfSigned generates one certificate shared by both fakes, so a single CA
// file makes the proxy trust them.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()

	cfg, err := smtpsrv.BuildTLSConfig(config.TLS{SelfSigned: true, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("generating a certificate: %v", err)
	}
	return cfg.Certificates[0]
}

func writeCertPEM(t *testing.T, cert tls.Certificate) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "upstream-ca.pem")
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing the CA file: %v", err)
	}
	return path
}

func generateKey(t *testing.T) string {
	t.Helper()

	spec, err := appcrypto.GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return spec
}
