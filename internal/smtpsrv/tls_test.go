package smtpsrv

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
)

// writeCertPair generates a self-signed pair and writes it to disk, returning
// the two paths.
func writeCertPair(t *testing.T, dir, commonName string) (certPath, keyPath string) {
	t.Helper()

	cert, err := generateSelfSigned()
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}

	certPath = filepath.Join(dir, commonName+".crt")
	keyPath = filepath.Join(dir, commonName+".key")

	certPEM, keyPEM, err := encodePair(cert)
	if err != nil {
		t.Fatalf("encoding the pair: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	return certPath, keyPath
}

func TestBuildTLSConfigSelfSigned(t *testing.T) {
	t.Parallel()

	cfg, err := BuildTLSConfig(config.TLS{SelfSigned: true, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("BuildTLSConfig returned nil for a self-signed configuration")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}

	leaf := cfg.Certificates[0].Leaf
	if leaf == nil {
		t.Fatal("the generated certificate has no parsed leaf")
	}
	// A self-signed certificate that quietly works for a decade invites being
	// left in production.
	if leaf.NotAfter.After(time.Now().Add(selfSignedValidity + 24*time.Hour)) {
		t.Errorf("NotAfter = %v, want at most about a year out", leaf.NotAfter)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("the certificate does not cover localhost: %v", err)
	}
}

func TestBuildTLSConfigMinVersion(t *testing.T) {
	t.Parallel()

	tests := map[string]uint16{
		"":    tls.VersionTLS12,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}
	for in, want := range tests {
		cfg, err := BuildTLSConfig(config.TLS{SelfSigned: true, MinVersion: in})
		if err != nil {
			t.Fatalf("BuildTLSConfig(%q): %v", in, err)
		}
		if cfg.MinVersion != want {
			t.Errorf("MinVersion for %q = %x, want %x", in, cfg.MinVersion, want)
		}
	}

	if _, err := BuildTLSConfig(config.TLS{SelfSigned: true, MinVersion: "1.0"}); err == nil {
		t.Error("BuildTLSConfig accepted TLS 1.0")
	}
}

func TestBuildTLSConfigWithoutAnyCertificate(t *testing.T) {
	t.Parallel()

	// "No TLS configured" is a valid outcome, not an error: a listener with
	// tls: none needs no certificate.
	cfg, err := BuildTLSConfig(config.TLS{MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Errorf("BuildTLSConfig = %v, want nil", cfg)
	}
}

func TestBuildTLSConfigFromFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "first")

	cfg, err := BuildTLSConfig(config.TLS{CertFile: certPath, KeyFile: keyPath, MinVersion: "1.2"})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("GetCertificate was not installed, so renewals would not be picked up")
	}
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"}); err != nil {
		t.Errorf("GetCertificate: %v", err)
	}
}

func TestBuildTLSConfigFailsFastOnABadPath(t *testing.T) {
	t.Parallel()

	// A typo in a path must fail at startup, not on the first client.
	dir := t.TempDir()
	_, err := BuildTLSConfig(config.TLS{
		CertFile: filepath.Join(dir, "missing.crt"),
		KeyFile:  filepath.Join(dir, "missing.key"),
	})
	if err == nil {
		t.Error("BuildTLSConfig accepted a certificate path that does not exist")
	}
}

func TestCertReloaderPicksUpARenewal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "cert")

	r := &certReloader{certFile: certPath, keyFile: keyPath}
	first, err := r.load()
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	firstSerial := leafOf(t, first).SerialNumber

	// Overwrite the pair, as cert-manager or certbot would on renewal.
	renewed, keyPEM := regeneratePair(t)
	if err := os.WriteFile(certPath, renewed, 0o600); err != nil {
		t.Fatalf("writing the renewed certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the renewed key: %v", err)
	}
	// Make the change visible regardless of filesystem timestamp granularity.
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("touching the certificate: %v", err)
	}

	second, err := r.load()
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if leafOf(t, second).SerialNumber.Cmp(firstSerial) == 0 {
		t.Error("the reloader kept serving the old certificate after a renewal")
	}
}

func TestCertReloaderKeepsServingThroughAHalfWrittenRenewal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "cert")

	r := &certReloader{certFile: certPath, keyFile: keyPath}
	if _, err := r.load(); err != nil {
		t.Fatalf("first load: %v", err)
	}

	// A renewal caught mid-write leaves an unparseable file. Taking the
	// listener down for that would be worse than serving the previous
	// certificate for a few more seconds.
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0o600); err != nil {
		t.Fatalf("truncating the certificate: %v", err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("touching the certificate: %v", err)
	}

	cert, err := r.load()
	if err != nil {
		t.Fatalf("load during a half-written renewal = %v, want the previous certificate", err)
	}
	if cert == nil {
		t.Fatal("load returned no certificate")
	}
}

func TestCertReloaderCachesBetweenChecks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "cert")

	r := &certReloader{certFile: certPath, keyFile: keyPath}
	first, err := r.get(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	second, err := r.get(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	// A busy server must not stat the filesystem on every handshake.
	if first != second {
		t.Error("two consecutive handshakes reloaded the certificate from disk")
	}
}

func leafOf(t *testing.T, cert *tls.Certificate) *x509.Certificate {
	t.Helper()

	if cert.Leaf != nil {
		return cert.Leaf
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return leaf
}

// encodePair PEM-encodes a generated certificate and its key.
func encodePair(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("the generated key is not an ECDSA key")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, nil
}

// regeneratePair returns a fresh PEM-encoded certificate and key, standing in
// for what a renewal writes.
func regeneratePair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	cert, err := generateSelfSigned()
	if err != nil {
		t.Fatalf("generateSelfSigned: %v", err)
	}
	certPEM, keyPEM, err = encodePair(cert)
	if err != nil {
		t.Fatalf("encoding the pair: %v", err)
	}
	return certPEM, keyPEM
}
