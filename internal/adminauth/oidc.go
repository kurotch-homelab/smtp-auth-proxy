package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// Single sign-on errors.
var (
	// ErrOIDCDisabled means single sign-on is not configured.
	ErrOIDCDisabled = errors.New("adminauth: single sign-on is not configured")
	// ErrNoRole means the identity provider authenticated the user but no role
	// could be derived, so the sign-in is refused.
	ErrNoRole = errors.New("adminauth: the identity provider returned no claim matching a role")
	// ErrSignupDisabled means the user is unknown and automatic provisioning is
	// off.
	ErrSignupDisabled = errors.New("adminauth: this account has not been added to the proxy")
	// ErrBadState means the callback did not match the request that started it.
	ErrBadState = errors.New("adminauth: the single sign-on response did not match the request")
)

// CallbackPath is where the identity provider returns the user. It forms the
// redirect URI together with the configured base URL, and must match what is
// registered with the provider exactly.
const CallbackPath = "/api/v1/auth/oidc/callback"

// OIDCConfig configures single sign-on.
type OIDCConfig struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// BaseURL is the proxy's externally reachable origin.
	BaseURL string

	// UsernameClaim identifies the user, e.g. preferred_username.
	UsernameClaim string
	// RoleClaim is inspected for role mapping, e.g. groups.
	RoleClaim string
	// RoleMappings maps a claim value to a role.
	RoleMappings map[string]string
	// DefaultRole applies when no mapping matches. Empty denies the sign-in,
	// which is the safe default for a tenant-wide directory.
	DefaultRole string
	// AllowSignup provisions an account on first successful sign-in.
	AllowSignup bool
}

// OIDCAuthenticator drives the authorization code flow.
type OIDCAuthenticator struct {
	cfg      OIDCConfig
	db       *store.DB
	log      *slog.Logger
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// NewOIDCAuthenticator discovers the provider's metadata and returns an
// authenticator. It returns nil when single sign-on is disabled.
func NewOIDCAuthenticator(ctx context.Context, cfg OIDCConfig, db *store.DB, client *http.Client, log *slog.Logger) (*OIDCAuthenticator, error) {
	if !cfg.Enabled {
		return nil, nil //nolint:nilnil // "not configured" is a valid outcome
	}
	if log == nil {
		log = slog.Default()
	}
	if client != nil {
		ctx = oidc.ClientContext(ctx, client)
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("adminauth: discovering the identity provider at %s: %w", cfg.Issuer, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	return &OIDCAuthenticator{
		cfg:      cfg,
		db:       db,
		log:      log,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  strings.TrimRight(cfg.BaseURL, "/") + CallbackPath,
			Scopes:       scopes,
		},
	}, nil
}

// AuthRequest is the state a sign-in needs to carry across the redirect.
type AuthRequest struct {
	// URL is where to send the browser.
	URL string
	// State and Nonce are stored in a short-lived cookie and checked on return.
	State string
	Nonce string
	// Verifier is the PKCE code verifier.
	Verifier string
}

// Start begins the authorization code flow.
//
// PKCE is used even though this is a confidential client: it costs nothing and
// removes any value in an intercepted authorization code.
func (a *OIDCAuthenticator) Start() (*AuthRequest, error) {
	state, err := appcrypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("adminauth: generating state: %w", err)
	}
	nonce, err := appcrypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("adminauth: generating a nonce: %w", err)
	}
	verifier := oauth2.GenerateVerifier()

	url := a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)

	return &AuthRequest{URL: url, State: state, Nonce: nonce, Verifier: verifier}, nil
}

// Claims is what the proxy reads out of an ID token.
//
// Everything is read out of the raw map rather than decoded into typed fields.
// Providers disagree about the shape of the same claim — "groups" arrives as a
// single string from some and an array from others — and a typed decode fails
// the whole sign-in on the mismatch rather than on the part that actually
// matters.
type Claims struct {
	Subject           string
	Email             string
	PreferredUsername string
	Name              string
	// raw keeps everything, so a deployment can map on a claim this struct does
	// not name.
	raw map[string]any
}

// Complete exchanges the code, verifies the ID token and resolves the user.
func (a *OIDCAuthenticator) Complete(ctx context.Context, code string, req AuthRequest, returnedState string, client *http.Client) (*store.AdminUser, error) {
	if returnedState == "" || !appcrypto.ConstantTimeEqual(returnedState, req.State) {
		return nil, ErrBadState
	}
	if client != nil {
		ctx = oidc.ClientContext(ctx, client)
	}

	token, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(req.Verifier))
	if err != nil {
		return nil, fmt.Errorf("adminauth: exchanging the authorization code: %w", err)
	}

	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("adminauth: the identity provider returned no ID token")
	}

	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("adminauth: verifying the ID token: %w", err)
	}
	// The nonce ties the token to the request that asked for it, which is what
	// stops a token obtained elsewhere from being replayed here.
	if !appcrypto.ConstantTimeEqual(idToken.Nonce, req.Nonce) {
		return nil, ErrBadState
	}

	claims, err := readClaims(idToken)
	if err != nil {
		return nil, err
	}
	return a.resolveUser(ctx, claims)
}

func readClaims(idToken *oidc.IDToken) (*Claims, error) {
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("adminauth: reading the ID token claims: %w", err)
	}

	c := &Claims{raw: raw, Subject: idToken.Subject}
	c.Email = c.value("email")
	c.PreferredUsername = c.value("preferred_username")
	c.Name = c.value("name")
	return c, nil
}

// resolveUser maps claims onto an account, provisioning one if allowed.
func (a *OIDCAuthenticator) resolveUser(ctx context.Context, claims *Claims) (*store.AdminUser, error) {
	role, err := a.roleFor(claims)
	if err != nil {
		return nil, err
	}

	existing, err := a.db.Users().GetBySubject(ctx, store.SourceOIDC, claims.Subject)
	switch {
	case err == nil:
		return a.syncExisting(ctx, existing, claims, role)
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	if !a.cfg.AllowSignup {
		return nil, ErrSignupDisabled
	}
	return a.provision(ctx, claims, role)
}

// syncExisting keeps the stored account in step with the provider.
//
// The role is re-derived on every sign-in, so removing someone from a group in
// the directory takes effect the next time they sign in rather than requiring
// a separate change here.
func (a *OIDCAuthenticator) syncExisting(ctx context.Context, user *store.AdminUser, claims *Claims, role store.Role) (*store.AdminUser, error) {
	if user.Disabled {
		return nil, ErrInvalidCredentials
	}

	roleChanged := user.Role != role
	user.Role = role
	if name := a.usernameFor(claims); name != "" {
		user.Username = name
	}
	user.Email = claims.Email
	user.DisplayName = claims.Name

	if err := a.db.Users().Update(ctx, user); err != nil {
		return nil, err
	}
	if roleChanged {
		// A demotion must take effect immediately, not whenever they next sign
		// out.
		if _, err := a.db.Sessions().DeleteForUser(ctx, user.ID); err != nil {
			a.log.Warn("could not revoke sessions after a role change",
				"username", user.Username, "reason", err)
		}
		a.log.Info("single sign-on changed a user's role",
			"username", user.Username, "role", role)
	}
	if err := a.db.Users().RecordSuccessfulLogin(ctx, user.ID); err != nil {
		a.log.Warn("could not record a successful sign-in", "username", user.Username, "reason", err)
	}
	return user, nil
}

func (a *OIDCAuthenticator) provision(ctx context.Context, claims *Claims, role store.Role) (*store.AdminUser, error) {
	username := a.usernameFor(claims)
	if username == "" {
		return nil, fmt.Errorf("adminauth: the identity provider returned no %q claim to use as a username",
			a.cfg.UsernameClaim)
	}

	user := &store.AdminUser{
		Username:    username,
		Email:       claims.Email,
		DisplayName: claims.Name,
		Role:        role,
		Source:      store.SourceOIDC,
		Subject:     store.NullString(claims.Subject),
	}
	if err := a.db.Users().Create(ctx, user); err != nil {
		return nil, err
	}

	a.log.Info("provisioned a user from single sign-on",
		"username", username, "role", role, "subject", claims.Subject)
	if err := a.db.Users().RecordSuccessfulLogin(ctx, user.ID); err != nil {
		a.log.Warn("could not record a successful sign-in", "username", username, "reason", err)
	}
	return user, nil
}

// roleFor maps the configured claim onto a role.
func (a *OIDCAuthenticator) roleFor(claims *Claims) (store.Role, error) {
	values := claims.values(a.cfg.RoleClaim)

	// The most privileged match wins, so someone in both an operators and an
	// admins group gets admin rather than whichever the provider listed first.
	best := store.Role("")
	for _, v := range values {
		mapped, ok := a.cfg.RoleMappings[v]
		if !ok {
			continue
		}
		role, err := ParseRole(mapped)
		if err != nil {
			a.log.Warn("a role mapping names a role this build does not know",
				"claim_value", v, "role", mapped)
			continue
		}
		if best == "" || morePrivileged(role, best) {
			best = role
		}
	}
	if best != "" {
		return best, nil
	}

	if a.cfg.DefaultRole == "" {
		return "", ErrNoRole
	}
	return ParseRole(a.cfg.DefaultRole)
}

// morePrivileged reports whether a outranks b.
func morePrivileged(a, b store.Role) bool {
	return rank(a) > rank(b)
}

func rank(r store.Role) int {
	switch r {
	case store.RoleAdmin:
		return 3
	case store.RoleOperator:
		return 2
	case store.RoleViewer:
		return 1
	default:
		return 0
	}
}

func (a *OIDCAuthenticator) usernameFor(claims *Claims) string {
	if name := claims.value(a.cfg.UsernameClaim); name != "" {
		return name
	}
	// Fall back through the claims most providers actually populate.
	for _, candidate := range []string{claims.PreferredUsername, claims.Email, claims.Subject} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

// value returns a single string claim.
func (c *Claims) value(name string) string {
	if name == "" {
		return ""
	}
	switch v := c.raw[name].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

// values returns a claim as a list, accepting either a single string or an
// array — providers differ, and a deployment should not have to care.
func (c *Claims) values(name string) []string {
	if name == "" {
		return nil
	}
	switch v := c.raw[name].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return nil
	}
}

// StateCookie carries the pending sign-in across the redirect.
//
// It is a short-lived, HttpOnly cookie rather than server-side state, so a
// deployment with several replicas does not need the callback to land on the
// same one that started the flow.
//
// session cookie; see the note there.
//
//nolint:gosec // G124: Secure is configurable for the same reason as the
func StateCookie(name, value string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     CallbackPath,
		HttpOnly: true,
		Secure:   secure,
		// The provider redirects back with a top-level GET, which Strict would
		// drop.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((10 * time.Minute).Seconds()),
	}
}
