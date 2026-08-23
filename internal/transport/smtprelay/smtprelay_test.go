package smtprelay_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	appconfig "github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/fakeexchange"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport/smtprelay"
)

// fakeTokens hands out a fixed token, or an error.
type fakeTokens struct {
	token string
	err   error
	// scopes records what was asked for, so a test can check the Exchange
	// Online scope is the one used.
	scopes []string
}

func (f *fakeTokens) Token(_ context.Context, _ *store.OAuthCredential, scope string) (oauth.Token, error) {
	f.scopes = append(f.scopes, scope)
	if f.err != nil {
		return oauth.Token{}, f.err
	}
	return oauth.Token{AccessToken: f.token, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

const exchangeScope = "https://outlook.office365.com/.default"

// setup starts a fake Exchange and a relay pointed at it.
func setup(t *testing.T, tokens *fakeTokens) (*fakeexchange.Server, *smtprelay.Relay) {
	t.Helper()

	cert := selfSignedCert(t)
	fake := fakeexchange.Start(t, cert)

	relay, err := smtprelay.New(smtprelay.Options{
		Host:      fake.Host(),
		Port:      fake.Port(),
		Scope:     exchangeScope,
		LocalName: "proxy.test",
		Timeout:   10 * time.Second,
		// The fake serves a self-signed certificate.
		TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		Tokens:    tokens,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("smtprelay.New: %v", err)
	}
	return fake, relay
}

// selfSignedCert borrows the proxy's own generator so the fake needs no
// checked-in key material.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	cfg, err := smtpsrv.BuildTLSConfig(appconfig.TLS{SelfSigned: true, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("generating a certificate: %v", err)
	}
	return cfg.Certificates[0]
}

func testMessage() *transport.Message {
	return &transport.Message{
		ID:         "msg-1",
		Mailbox:    &store.Mailbox{ID: "mb-1", Address: "shared@example.com", Enabled: true},
		Credential: &store.OAuthCredential{ID: "cred-1", Name: "primary", ClientID: "client"},
		Recipients: []string{"ops@example.net"},
		Raw:        []byte("From: shared@example.com\r\nTo: ops@example.net\r\nSubject: hi\r\n\r\nbody\r\n"),
	}
}

func TestSendDelivers(t *testing.T) {
	t.Parallel()

	tokens := &fakeTokens{token: "T0K3N"}
	fake, relay := setup(t, tokens)

	if err := relay.Send(t.Context(), testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deliveries := fake.Deliveries()
	if len(deliveries) != 1 {
		t.Fatalf("the fake accepted %d messages, want 1", len(deliveries))
	}
	d := deliveries[0]

	// The mailbox goes in the XOAUTH2 user field: that substitution is what
	// lets one application registration send as many shared mailboxes.
	if d.AuthUser != "shared@example.com" {
		t.Errorf("XOAUTH2 user = %q, want the mailbox address", d.AuthUser)
	}
	if d.AuthToken != "T0K3N" {
		t.Errorf("XOAUTH2 token = %q", d.AuthToken)
	}
	// Assert the exact wire bytes, separators included.
	want := "user=shared@example.com\x01auth=Bearer T0K3N\x01\x01"
	if string(d.RawXOAuth2) != want {
		t.Errorf("XOAUTH2 bytes =\n %q\nwant\n %q", d.RawXOAuth2, want)
	}

	// The envelope sender must be the mailbox, not whatever the client asked
	// for: Exchange requires the submitting identity to match.
	if d.EnvelopeFrom != "shared@example.com" {
		t.Errorf("envelope sender = %q, want the mailbox address", d.EnvelopeFrom)
	}
	if len(d.Recipients) != 1 || d.Recipients[0] != "ops@example.net" {
		t.Errorf("recipients = %v", d.Recipients)
	}
	if !strings.Contains(d.Data, "Subject: hi") || !strings.Contains(d.Data, "body") {
		t.Errorf("the message did not arrive intact:\n%s", d.Data)
	}

	if len(tokens.scopes) != 1 || tokens.scopes[0] != exchangeScope {
		t.Errorf("token scopes = %v, want the Exchange Online scope", tokens.scopes)
	}
}

func TestSendPreservesTheMessageByteForByte(t *testing.T) {
	t.Parallel()

	tokens := &fakeTokens{token: "T0K3N"}
	fake, relay := setup(t, tokens)

	m := testMessage()
	// A body line starting with a dot must survive dot-stuffing intact.
	m.Raw = []byte("From: shared@example.com\r\nTo: ops@example.net\r\n\r\n.leading dot\r\nnormal\r\n")

	if err := relay.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := fake.Deliveries()[0].Data
	if !strings.Contains(got, ".leading dot") {
		t.Errorf("dot-stuffing was not undone correctly:\n%q", got)
	}
}

func TestSendClassifiesFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		behavior      fakeexchange.Behavior
		wantPermanent bool
		wantCode      string
		wantAuth      bool
	}{
		{
			// A 5xx is final: the message will never be deliverable.
			name:          "permanent rejection at MAIL FROM",
			behavior:      fakeexchange.Behavior{RejectMailFrom: "550 5.7.60 SendAsDenied"},
			wantPermanent: true,
			wantCode:      "5.7.60",
		},
		{
			name:          "permanent rejection at RCPT TO",
			behavior:      fakeexchange.Behavior{RejectRcptTo: "550 5.1.1 User unknown"},
			wantPermanent: true,
			wantCode:      "5.1.1",
		},
		{
			// The throttling response a mailbox over its budget sees.
			name:     "server busy is retried",
			behavior: fakeexchange.Behavior{RejectData: "451 4.7.500 Server busy"},
			wantCode: "4.7.500",
		},
		{
			name:     "temporary rejection at MAIL FROM",
			behavior: fakeexchange.Behavior{RejectMailFrom: "451 4.3.2 Try again later"},
			wantCode: "4.3.2",
		},
		{
			// 535 is a permanent SMTP code, but it almost always means a tenant
			// setting is missing, so the queue keeps the mail and retries.
			name:     "authentication failure is retried, not dropped",
			behavior: fakeexchange.Behavior{RejectAuth: true},
			wantCode: "5.7.3",
			wantAuth: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake, relay := setup(t, &fakeTokens{token: "T0K3N"})
			fake.SetBehavior(tt.behavior)

			err := relay.Send(t.Context(), testMessage())
			if err == nil {
				t.Fatal("Send succeeded despite the rejection")
			}

			var terr *transport.Error
			if !errors.As(err, &terr) {
				t.Fatalf("Send returned %T, want *transport.Error", err)
			}
			if terr.Permanent != tt.wantPermanent {
				t.Errorf("Permanent = %v, want %v (error: %v)", terr.Permanent, tt.wantPermanent, err)
			}
			if tt.wantCode != "" && terr.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", terr.Code, tt.wantCode)
			}
			if transport.IsAuthFailure(err) != tt.wantAuth {
				t.Errorf("IsAuthFailure = %v, want %v", transport.IsAuthFailure(err), tt.wantAuth)
			}
			if len(fake.Deliveries()) != 0 {
				t.Error("a rejected message was recorded as delivered")
			}
		})
	}
}

// An operator seeing "535 5.7.3 Authentication unsuccessful" has no way to know
// which of the three tenant steps is missing, so the error says.
func TestAuthFailureExplainsWhatToCheck(t *testing.T) {
	t.Parallel()

	fake, relay := setup(t, &fakeTokens{token: "T0K3N"})
	fake.SetBehavior(fakeexchange.Behavior{RejectAuth: true})

	err := relay.Send(t.Context(), testMessage())
	if err == nil {
		t.Fatal("Send succeeded")
	}
	for _, want := range []string{"SMTP.SendAsApp", "New-ServicePrincipal", "Add-MailboxPermission"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s:\n%v", want, err)
		}
	}
}

func TestTokenFailureIsRetried(t *testing.T) {
	t.Parallel()

	_, relay := setup(t, &fakeTokens{err: errors.New("the secret expired")})

	err := relay.Send(t.Context(), testMessage())
	if err == nil {
		t.Fatal("Send succeeded without a token")
	}
	// A credential problem is usually fixable; the mail should wait, not die.
	if transport.IsPermanent(err) {
		t.Errorf("a token failure was treated as permanent: %v", err)
	}
}

func TestUnreachableUpstreamIsRetried(t *testing.T) {
	t.Parallel()

	relay, err := smtprelay.New(smtprelay.Options{
		// Port 1 on the loopback interface refuses connections.
		Host: "127.0.0.1", Port: 1,
		Scope:   exchangeScope,
		Timeout: 2 * time.Second,
		Tokens:  &fakeTokens{token: "T0K3N"},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("smtprelay.New: %v", err)
	}

	sendErr := relay.Send(t.Context(), testMessage())
	if sendErr == nil {
		t.Fatal("Send succeeded against a closed port")
	}
	if transport.IsPermanent(sendErr) {
		t.Errorf("an unreachable upstream was treated as permanent: %v", sendErr)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()

	tests := map[string]smtprelay.Options{
		"no token source": {Host: "smtp.example.com", Scope: exchangeScope},
		"no host":         {Scope: exchangeScope, Tokens: &fakeTokens{}},
		"no scope":        {Host: "smtp.example.com", Tokens: &fakeTokens{}},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := smtprelay.New(opts); err == nil {
				t.Error("New accepted invalid options")
			}
		})
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	_, relay := setup(t, &fakeTokens{token: "T0K3N"})
	if got := relay.Name(); got != "smtp" {
		t.Errorf("Name() = %q, want smtp", got)
	}
}
