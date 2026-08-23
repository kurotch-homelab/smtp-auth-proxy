package adminauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Session errors.
var (
	// ErrNoSession means the request carried no usable session.
	ErrNoSession = errors.New("adminauth: not signed in")
	// ErrCSRF means a state-changing request failed its CSRF check.
	ErrCSRF = errors.New("adminauth: CSRF token missing or incorrect")
)

// CSRFHeader is where the UI sends the token for a state-changing request.
const CSRFHeader = "X-CSRF-Token"

// SessionConfig controls cookie and lifetime behavior.
type SessionConfig struct {
	CookieName string
	// Lifetime is the absolute cap on a session, whatever the activity.
	Lifetime time.Duration
	// IdleTimeout ends a session that has gone unused.
	IdleTimeout time.Duration
	// Secure marks the cookie Secure. It should only be false for a deployment
	// genuinely served over plain http, which is itself a bad idea.
	Secure bool
	// Path scopes the cookie; usually "/".
	Path string
}

// SessionManager issues, validates and revokes admin sessions.
type SessionManager struct {
	db  *store.DB
	cfg SessionConfig
}

// NewSessionManager returns a manager.
func NewSessionManager(db *store.DB, cfg SessionConfig) *SessionManager {
	if cfg.CookieName == "" {
		cfg.CookieName = "sap_session"
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = 12 * time.Hour
	}
	return &SessionManager{db: db, cfg: cfg}
}

// Issued is a newly created session and the token to hand the browser.
type Issued struct {
	Session *store.Session
	// Token goes in the cookie. It is returned once and never stored, so this
	// is the only moment it exists outside the browser.
	Token string
	// CSRFToken is readable by the UI and echoed back in a header.
	CSRFToken string
}

// Issue creates a session for a user.
func (m *SessionManager) Issue(ctx context.Context, user *store.AdminUser, r *http.Request) (*Issued, error) {
	token, err := appcrypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("adminauth: generating a session token: %w", err)
	}
	csrf, err := appcrypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("adminauth: generating a CSRF token: %w", err)
	}

	now := time.Now().UTC()
	s := &store.Session{
		UserID:    user.ID,
		TokenHash: store.HashSessionToken(token),
		CSRFToken: csrf,
		IP:        ClientIP(r, nil),
		UserAgent: truncate(r.UserAgent(), 512),
		CreatedAt: now,
		ExpiresAt: now.Add(m.cfg.Lifetime),
	}
	if err := m.db.Sessions().Create(ctx, s); err != nil {
		return nil, err
	}

	return &Issued{Session: s, Token: token, CSRFToken: csrf}, nil
}

// Cookie builds the session cookie for a token.
//
// over plain http cannot set it, and forcing it there would silently break
// sign-in rather than protect anything; the configuration warns loudly instead.
//
//nolint:gosec // G124: Secure is deliberately configurable. A deployment served
func (m *SessionManager) Cookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:  m.cfg.CookieName,
		Value: token,
		Path:  m.cfg.Path,
		// HttpOnly keeps the token out of reach of any script on the page, so a
		// cross-site scripting bug cannot walk off with a session.
		HttpOnly: true,
		Secure:   m.cfg.Secure,
		// Lax rather than Strict: the OIDC provider redirects back with a
		// top-level GET, and Strict would drop the cookie on that navigation.
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
}

// ClearCookie builds the cookie that removes a session from the browser.
//
//nolint:gosec // G124: see the note on Cookie.
func (m *SessionManager) ClearCookie() *http.Cookie {
	c := m.Cookie("", time.Unix(0, 0))
	c.MaxAge = -1
	return c
}

// Authenticate resolves the session on a request.
func (m *SessionManager) Authenticate(ctx context.Context, r *http.Request) (*store.Authenticated, error) {
	cookie, err := r.Cookie(m.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		return nil, ErrNoSession
	}

	auth, err := m.db.Sessions().Lookup(ctx, cookie.Value, m.cfg.IdleTimeout)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, err
	}

	// Recording activity is what makes the idle timeout measure inactivity
	// rather than age. A failure here must not fail the request.
	_ = m.db.Sessions().Touch(ctx, auth.Session.ID)
	return auth, nil
}

// CheckCSRF validates a state-changing request.
//
// The token is compared in constant time, and the comparison is against the
// value stored with the session rather than a second cookie: a double-submit
// cookie can be planted by a subdomain, and this cannot.
func (m *SessionManager) CheckCSRF(auth *store.Authenticated, r *http.Request) error {
	if isSafeMethod(r.Method) {
		return nil
	}
	presented := r.Header.Get(CSRFHeader)
	if presented == "" || !appcrypto.ConstantTimeEqual(presented, auth.Session.CSRFToken) {
		return ErrCSRF
	}
	return nil
}

// Revoke ends one session.
func (m *SessionManager) Revoke(ctx context.Context, sessionID string) error {
	return m.db.Sessions().Delete(ctx, sessionID)
}

// RevokeAllForUser ends every session a user holds.
func (m *SessionManager) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := m.db.Sessions().DeleteForUser(ctx, userID)
	return err
}

// Lifetime reports the configured absolute session lifetime.
func (m *SessionManager) Lifetime() time.Duration { return m.cfg.Lifetime }

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// ClientIP returns the address to record for a request.
//
// X-Forwarded-For is only believed from a proxy the operator listed as trusted.
// Believing it from anywhere would let any client write whatever it liked into
// the audit log and dodge login rate limiting.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	remote := remoteIP(r.RemoteAddr)
	if len(trusted) == 0 || remote == nil {
		return remote.String()
	}

	if !containsIP(trusted, remote) {
		return remote.String()
	}

	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return remote.String()
	}
	// The left-most entry is the original client; the rest are proxies.
	first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
	if ip := net.ParseIP(first); ip != nil {
		return ip.String()
	}
	return remote.String()
}

// ParseTrustedProxies turns the configured CIDRs into networks.
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("adminauth: invalid trusted proxy %q: %w", c, err)
		}
		out = append(out, network)
	}
	return out, nil
}

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
