package fakeexchange_test

import (
	"crypto/tls"
	"testing"

	appconfig "github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/fakeexchange"
)

func cert(t *testing.T) tls.Certificate {
	t.Helper()

	cfg, err := smtpsrv.BuildTLSConfig(appconfig.TLS{SelfSigned: true, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("generating a certificate: %v", err)
	}
	return cfg.Certificates[0]
}

func TestStartReportsItsAddress(t *testing.T) {
	t.Parallel()

	s := fakeexchange.Start(t, cert(t))
	if s.Host() == "" || s.Port() == 0 {
		t.Errorf("Host()/Port() = %q/%d, want a bound address", s.Host(), s.Port())
	}
	if s.Addr() == "" {
		t.Error("Addr() is empty")
	}
	if len(s.Deliveries()) != 0 {
		t.Error("a fresh server already has deliveries")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	t.Parallel()

	s := fakeexchange.Start(t, cert(t))
	s.Stop()
	// The test cleanup calls Stop again; a second call must not panic or hang.
	s.Stop()
}

func TestSetBehavior(t *testing.T) {
	t.Parallel()

	s := fakeexchange.Start(t, cert(t))
	s.SetBehavior(fakeexchange.Behavior{RejectAuth: true})
	// Exercised for real by the smtprelay tests; this only checks the setter
	// is safe to call before any connection arrives.
}
