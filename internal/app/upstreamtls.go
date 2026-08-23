package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
)

// upstreamTLSConfig builds the client TLS settings used for both Microsoft
// Entra and Exchange Online.
//
// It returns nil when nothing is customized, which lets each transport apply
// its own defaults — in particular the correct ServerName, which this function
// cannot know.
func upstreamTLSConfig(cfg config.UpstreamTLS) (*tls.Config, error) {
	if cfg.CAFile == "" && !cfg.InsecureSkipVerify {
		return nil, nil //nolint:nilnil // "nothing to customize" is the normal case
	}

	out := &tls.Config{
		MinVersion: tls.VersionTLS12,
		//nolint:gosec // G402: opt-in, warned about at startup, and documented
		// as being for a test lab. Refusing to implement it would only push
		// operators towards worse workarounds.
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CAFile == "" {
		return out, nil
	}

	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("app: reading upstream.tls.ca_file: %w", err)
	}

	// Start from the system roots so adding a private authority does not
	// silently stop the real Microsoft endpoints from verifying.
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("app: upstream.tls.ca_file (%s) contains no usable certificates", cfg.CAFile)
	}
	out.RootCAs = pool

	return out, nil
}
