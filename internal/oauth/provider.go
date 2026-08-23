// Package oauth obtains access tokens for Microsoft 365 using the OAuth 2.0
// client credentials flow.
//
// Exchange Online supports this flow for SMTP AUTH: an application registration
// granted the SMTP.SendAsApp permission requests a token for the
// https://outlook.office365.com/.default scope, and the mailbox to send as is
// selected by the XOAUTH2 "user=" field rather than by the token. That is what
// lets one registration serve every shared mailbox the tenant has granted it.
package oauth

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Token acquisition errors.
var (
	// ErrCredentialUnusable means the stored credential could not be turned
	// into something that can request a token — a secret that will not
	// decrypt, a certificate that will not parse.
	ErrCredentialUnusable = errors.New("oauth: credential is unusable")
	// ErrTokenRequestFailed means Microsoft Entra refused to issue a token.
	ErrTokenRequestFailed = errors.New("oauth: token request failed")
)

// Token is an access token and when it stops being valid.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// Expired reports whether the token is past its lifetime, with a margin so a
// token is never used in the last moments before it expires.
func (t Token) Expired(now time.Time, margin time.Duration) bool {
	return !now.Add(margin).Before(t.ExpiresAt)
}

// Usable reports whether the token can still start a delivery that may take a
// little while to finish.
func (t Token) Usable(now time.Time) bool {
	return t.AccessToken != "" && !t.Expired(now, RefreshMargin)
}

// TokenSource hands out access tokens for stored credentials.
type TokenSource interface {
	// Token returns a valid access token for a credential and scope.
	Token(ctx context.Context, cred *store.OAuthCredential, scope string) (Token, error)
}

// RefreshMargin is how far ahead of expiry a token stops being considered
// usable. Microsoft's access tokens last about an hour; five minutes leaves
// room for a delivery that started just before the boundary.
const RefreshMargin = 5 * time.Minute

// Provider is the default TokenSource. It keeps one MSAL client per credential
// and lets MSAL own the token cache.
type Provider struct {
	keyring    *appcrypto.Keyring
	httpClient *http.Client
	// instanceDiscovery asks Microsoft which endpoint serves a tenant.
	instanceDiscovery bool
	// defaultAuthorityHost is used for credentials that name no authority of
	// their own.
	defaultAuthorityHost string

	mu sync.Mutex
	// clients is keyed by credential identity *and* its material, so editing a
	// credential in the admin UI takes effect without a restart.
	clients map[string]*cachedClient
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithoutInstanceDiscovery stops the provider asking Microsoft which endpoint
// serves a tenant, and trusts the configured authority as given.
//
// Instance discovery is a request to login.microsoftonline.com regardless of
// which authority a credential names, so it has to be turned off for a
// deployment whose authority is a private or air-gapped endpoint — otherwise
// every token request waits for a host it cannot reach.
func WithoutInstanceDiscovery() ProviderOption {
	return func(p *Provider) { p.instanceDiscovery = false }
}

// WithDefaultAuthorityHost sets the login host used for credentials that do not
// name one. Without it every such credential would go to the worldwide
// commercial cloud regardless of what the deployment configured, which is wrong
// for a sovereign cloud and impossible to notice until mail stops.
func WithDefaultAuthorityHost(host string) ProviderOption {
	return func(p *Provider) {
		if host != "" {
			p.defaultAuthorityHost = host
		}
	}
}

type cachedClient struct {
	client confidential.Client
	// fingerprint changes whenever the credential's material changes.
	fingerprint string
}

// NewProvider returns a Provider. The keyring decrypts stored secrets;
// httpClient may be nil, in which case a sensible default is used.
func NewProvider(keyring *appcrypto.Keyring, httpClient *http.Client, opts ...ProviderOption) *Provider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	p := &Provider{
		keyring:              keyring,
		httpClient:           httpClient,
		instanceDiscovery:    true,
		defaultAuthorityHost: DefaultAuthorityHost,
		clients:              make(map[string]*cachedClient),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Token returns an access token for a credential and scope.
func (p *Provider) Token(ctx context.Context, cred *store.OAuthCredential, scope string) (Token, error) {
	if scope == "" {
		return Token{}, errors.New("oauth: a scope is required")
	}

	client, err := p.clientFor(cred)
	if err != nil {
		return Token{}, err
	}

	// MSAL checks its own cache first and only calls the network when it has
	// nothing usable, so there is no separate cache to keep in step here.
	result, err := client.AcquireTokenByCredential(ctx, []string{scope})
	if err != nil {
		return Token{}, fmt.Errorf("%w for %s: %w", ErrTokenRequestFailed, describe(cred), redactToken(err))
	}
	if result.AccessToken == "" {
		return Token{}, fmt.Errorf("%w for %s: the response contained no access token",
			ErrTokenRequestFailed, describe(cred))
	}

	return Token{AccessToken: result.AccessToken, ExpiresAt: result.ExpiresOn}, nil
}

// Forget drops the cached client for a credential, so the next request rebuilds
// it. The admin API calls this after a credential is edited or deleted.
func (p *Provider) Forget(credentialID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, credentialID)
}

func (p *Provider) clientFor(cred *store.OAuthCredential) (confidential.Client, error) {
	fingerprint := p.fingerprintOf(cred)

	p.mu.Lock()
	cached, ok := p.clients[cred.ID]
	p.mu.Unlock()

	if ok && cached.fingerprint == fingerprint {
		return cached.client, nil
	}

	client, err := p.buildClient(cred)
	if err != nil {
		return confidential.Client{}, err
	}

	p.mu.Lock()
	p.clients[cred.ID] = &cachedClient{client: client, fingerprint: fingerprint}
	p.mu.Unlock()

	return client, nil
}

func (p *Provider) buildClient(cred *store.OAuthCredential) (confidential.Client, error) {
	msalCred, err := p.credentialFor(cred)
	if err != nil {
		return confidential.Client{}, err
	}

	host := cred.AuthorityHost
	if host == "" {
		host = p.defaultAuthorityHost
	}
	authority, err := AuthorityURL(host, cred.TenantID)
	if err != nil {
		return confidential.Client{}, err
	}

	client, err := confidential.New(authority, cred.ClientID, msalCred,
		confidential.WithHTTPClient(p.httpClient),
		confidential.WithInstanceDiscovery(p.instanceDiscovery))
	if err != nil {
		return confidential.Client{}, fmt.Errorf("%w: building a client for %s: %w",
			ErrCredentialUnusable, describe(cred), err)
	}
	return client, nil
}

func (p *Provider) credentialFor(cred *store.OAuthCredential) (confidential.Credential, error) {
	switch cred.AuthType {
	case store.AuthTypeSecret:
		secret, err := p.keyring.DecryptString(cred.ClientSecretEnc, cred.SecretContext())
		if err != nil {
			return confidential.Credential{}, fmt.Errorf("%w: decrypting the client secret for %s: %w",
				ErrCredentialUnusable, describe(cred), err)
		}
		msalCred, err := confidential.NewCredFromSecret(secret)
		if err != nil {
			return confidential.Credential{}, fmt.Errorf("%w: %s: %w", ErrCredentialUnusable, describe(cred), err)
		}
		return msalCred, nil

	case store.AuthTypeCertificate:
		certs, key, err := p.certificateFor(cred)
		if err != nil {
			return confidential.Credential{}, err
		}
		msalCred, err := confidential.NewCredFromCert(certs, key)
		if err != nil {
			return confidential.Credential{}, fmt.Errorf("%w: %s: %w", ErrCredentialUnusable, describe(cred), err)
		}
		return msalCred, nil

	default:
		return confidential.Credential{}, fmt.Errorf("%w: %s has an unknown authentication type %q",
			ErrCredentialUnusable, describe(cred), cred.AuthType)
	}
}

func (p *Provider) certificateFor(cred *store.OAuthCredential) ([]*x509.Certificate, crypto.PrivateKey, error) {
	keyPEM, err := p.keyring.DecryptString(cred.CertificateKeyEnc, cred.CertificateKeyContext())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decrypting the certificate key for %s: %w",
			ErrCredentialUnusable, describe(cred), err)
	}

	// The certificate and its key are stored separately but MSAL wants them
	// parsed together, so they are concatenated here rather than in the store.
	combined := []byte(cred.CertificatePEM + "\n" + keyPEM)
	certs, key, err := confidential.CertFromPEM(combined, "")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parsing the certificate for %s: %w",
			ErrCredentialUnusable, describe(cred), err)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("%w: %s has no certificate", ErrCredentialUnusable, describe(cred))
	}
	return certs, key, nil
}

// AuthorityURL builds the Entra authority for a tenant, e.g.
// https://login.microsoftonline.com/<tenant>.
func AuthorityURL(host, tenantID string) (string, error) {
	if tenantID == "" {
		return "", errors.New("oauth: a tenant id is required")
	}
	if host == "" {
		host = DefaultAuthorityHost
	}
	return strings.TrimRight(host, "/") + "/" + tenantID, nil
}

// DefaultAuthorityHost is the worldwide commercial cloud. Sovereign clouds
// (GCC High, DoD, 21Vianet) override it per credential.
const DefaultAuthorityHost = "https://login.microsoftonline.com"

// fingerprintOf changes whenever anything that affects token acquisition
// changes, so an edited credential is not served from a stale client.
func (p *Provider) fingerprintOf(cred *store.OAuthCredential) string {
	h := sha256.New()
	for _, part := range []string{
		cred.TenantID, cred.ClientID, string(cred.AuthType), cred.AuthorityHost,
		cred.ClientSecretEnc, cred.CertificatePEM, cred.CertificateKeyEnc,
		p.defaultAuthorityHost,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// describe names a credential for an error message without revealing anything
// secret.
func describe(cred *store.OAuthCredential) string {
	if cred.Name != "" {
		return fmt.Sprintf("credential %q (client %s)", cred.Name, cred.ClientID)
	}
	return "client " + cred.ClientID
}

// redactToken removes anything token-shaped from an upstream error before it
// reaches a log. Entra's error bodies can echo back assertions.
func redactToken(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, marker := range []string{"access_token", "client_assertion", "client_secret", "refresh_token"} {
		if i := strings.Index(msg, marker); i >= 0 {
			return errors.New(strings.TrimSpace(msg[:i]) + " [redacted: the response mentioned " + marker + "]")
		}
	}
	return err
}
