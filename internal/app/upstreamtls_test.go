package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
)

func TestUpstreamTLSConfigDefaultsToNil(t *testing.T) {
	t.Parallel()

	// Nothing customized means each transport applies its own defaults,
	// including the ServerName this function cannot know.
	got, err := upstreamTLSConfig(config.UpstreamTLS{})
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if got != nil {
		t.Errorf("upstreamTLSConfig = %+v, want nil", got)
	}
}

func TestUpstreamTLSConfigInsecure(t *testing.T) {
	t.Parallel()

	got, err := upstreamTLSConfig(config.UpstreamTLS{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if got == nil || !got.InsecureSkipVerify {
		t.Fatalf("upstreamTLSConfig = %+v, want verification disabled", got)
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2 even with verification off", got.MinVersion)
	}
}

func TestUpstreamTLSConfigAddsACertificateAuthority(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	caPEM := generateCertPEM(t)
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatalf("writing the CA file: %v", err)
	}

	got, err := upstreamTLSConfig(config.UpstreamTLS{CAFile: path})
	if err != nil {
		t.Fatalf("upstreamTLSConfig: %v", err)
	}
	if got == nil || got.RootCAs == nil {
		t.Fatalf("upstreamTLSConfig = %+v, want a root pool", got)
	}
	// Starting from the system roots means adding a private authority does not
	// silently stop the real Microsoft endpoints from verifying. Subjects() is
	// deprecated and returns nothing for a system pool, so compare against a
	// pool built from our certificate alone.
	onlyOurs := x509.NewCertPool()
	if !onlyOurs.AppendCertsFromPEM(caPEM) {
		t.Fatal("the test certificate could not be parsed")
	}
	if got.RootCAs.Equal(onlyOurs) {
		t.Error("the pool replaced the system roots rather than adding to them")
	}
}

func TestUpstreamTLSConfigErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, err := upstreamTLSConfig(config.UpstreamTLS{CAFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Error("upstreamTLSConfig accepted a path that does not exist")
	}

	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_, err := upstreamTLSConfig(config.UpstreamTLS{CAFile: junk})
	if err == nil || !strings.Contains(err.Error(), "no usable certificates") {
		t.Errorf("upstreamTLSConfig = %v, want a clear error about the file contents", err)
	}
}

// generateCertPEM produces a throwaway certificate in PEM form.
func generateCertPEM(t *testing.T) []byte {
	t.Helper()

	cfg, err := smtpsrv.BuildTLSConfig(config.TLS{SelfSigned: true, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("generating a certificate: %v", err)
	}
	return encodeCertificatePEM(cfg.Certificates[0])
}

func encodeCertificatePEM(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}
