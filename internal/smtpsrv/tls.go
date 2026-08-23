package smtpsrv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
)

// selfSignedValidity is how long a generated certificate lasts. It is short on
// purpose: a self-signed certificate is for a first run or a test lab, and one
// that quietly works for a decade invites being left in place.
const selfSignedValidity = 365 * 24 * time.Hour

// BuildTLSConfig turns the TLS section of the configuration into a tls.Config.
//
// When cert_file and key_file are set the pair is reloaded from disk on every
// handshake, so a certificate renewed by cert-manager or certbot takes effect
// without restarting the proxy.
func BuildTLSConfig(cfg config.TLS) (*tls.Config, error) {
	minVersion, err := tlsVersion(cfg.MinVersion)
	if err != nil {
		return nil, err
	}

	base := &tls.Config{
		MinVersion: minVersion,
		// Devices that can only do TLS 1.2 also tend to have short cipher
		// lists. Leaving selection to Go keeps the secure defaults without
		// hard-coding a list that ages badly.
		NextProtos: nil,
	}

	switch {
	case cfg.CertFile != "" && cfg.KeyFile != "":
		reloader := &certReloader{certFile: cfg.CertFile, keyFile: cfg.KeyFile}
		// Load once now so a bad path fails at startup rather than on the first
		// client connection.
		if _, err := reloader.load(); err != nil {
			return nil, err
		}
		base.GetCertificate = reloader.get
		return base, nil

	case cfg.SelfSigned:
		cert, err := generateSelfSigned()
		if err != nil {
			return nil, err
		}
		base.Certificates = []tls.Certificate{cert}
		return base, nil

	default:
		return nil, nil //nolint:nilnil // "no TLS configured" is a valid outcome, not an error
	}
}

func tlsVersion(v string) (uint16, error) {
	switch v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("smtpsrv: unsupported TLS version %q; use 1.2 or 1.3", v)
	}
}

// certReloader serves the current certificate, reloading it when the files
// change on disk.
type certReloader struct {
	certFile string
	keyFile  string

	mu       sync.RWMutex
	cert     *tls.Certificate
	loadedAt time.Time
	modTime  time.Time
}

// reloadInterval bounds how often the files are stat'd, so a busy server does
// not hit the filesystem on every handshake.
const reloadInterval = 30 * time.Second

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, loadedAt := r.cert, r.loadedAt
	r.mu.RUnlock()

	if cert != nil && time.Since(loadedAt) < reloadInterval {
		return cert, nil
	}
	return r.load()
}

func (r *certReloader) load() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, statErr := os.Stat(r.certFile)
	// Nothing changed since the last load; just refresh the timer.
	if statErr == nil && r.cert != nil && info.ModTime().Equal(r.modTime) {
		r.loadedAt = time.Now()
		return r.cert, nil
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// A renewal that is halfway through writing the pair would otherwise
		// take the listener down; keep serving the previous certificate.
		if r.cert != nil {
			r.loadedAt = time.Now()
			return r.cert, nil
		}
		return nil, fmt.Errorf("smtpsrv: loading the TLS certificate: %w", err)
	}

	r.cert = &cert
	r.loadedAt = time.Now()
	if statErr == nil {
		r.modTime = info.ModTime()
	}
	return r.cert, nil
}

// generateSelfSigned creates an in-memory certificate covering localhost and
// the host's own addresses.
func generateSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("smtpsrv: generating a key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("smtpsrv: generating a serial number: %w", err)
	}

	hostname, _ := os.Hostname()
	names := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		names = append(names, hostname)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0], Organization: []string{"smtp-auth-proxy self-signed"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(selfSignedValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  localAddresses(),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("smtpsrv: creating a self-signed certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("smtpsrv: parsing the generated certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// localAddresses lists the host's own IPs, so a client connecting by address
// rather than name still matches the certificate.
func localAddresses() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			ips = append(ips, ipNet.IP)
		}
	}
	return ips
}
