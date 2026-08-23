// Package adminapi is the management HTTP interface: the JSON API the admin UI
// talks to, plus the UI itself served from the same binary.
package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/metrics"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/webui"
)

// Options configure the management interface.
type Options struct {
	DB      *store.DB
	Keyring *appcrypto.Keyring

	Sessions *adminauth.SessionManager
	Local    *adminauth.LocalAuthenticator
	// OIDC is nil when single sign-on is not configured.
	OIDC *adminauth.OIDCAuthenticator
	// OIDCClient is used for the code exchange, so a private certificate
	// authority applies there too.
	OIDCClient *http.Client

	// Tokens lets the connection test acquire a token, and lets an edited
	// credential take effect without a restart.
	Tokens *oauth.Provider
	// SMTPScope and GraphScope are what the connection test asks for.
	SMTPScope  string
	GraphScope string

	// TrustedProxies are the networks whose X-Forwarded-For is believed.
	TrustedProxies []string
	// CookieSecure marks the session and state cookies Secure.
	CookieSecure bool

	// Metrics exposes Prometheus metrics when enabled.
	MetricsEnabled bool
	MetricsPath    string
	Metrics        *metrics.Metrics

	// ServeUI mounts the embedded admin interface. Disabled in tests that only
	// exercise the API.
	ServeUI bool

	Log *slog.Logger
}

// Server is the management interface.
type Server struct {
	db      *store.DB
	keyring *appcrypto.Keyring

	sessions   *adminauth.SessionManager
	local      *adminauth.LocalAuthenticator
	oidc       *adminauth.OIDCAuthenticator
	oidcClient *http.Client
	tokens     *oauth.Provider
	smtpScope  string
	graphScope string

	trustedProxies []*net.IPNet
	cookieSecure   bool
	serveUI        bool

	metricsEnabled bool
	metricsPath    string
	metrics        *metrics.Metrics

	log     *slog.Logger
	handler http.Handler
}

// New builds the management interface.
func New(opts Options) (*Server, error) {
	if opts.DB == nil {
		return nil, errors.New("adminapi: a database is required")
	}
	if opts.Sessions == nil {
		return nil, errors.New("adminapi: a session manager is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.MetricsPath == "" {
		opts.MetricsPath = "/metrics"
	}

	trusted, err := adminauth.ParseTrustedProxies(opts.TrustedProxies)
	if err != nil {
		return nil, err
	}

	s := &Server{
		db:             opts.DB,
		keyring:        opts.Keyring,
		sessions:       opts.Sessions,
		local:          opts.Local,
		oidc:           opts.OIDC,
		oidcClient:     opts.OIDCClient,
		tokens:         opts.Tokens,
		smtpScope:      opts.SMTPScope,
		graphScope:     opts.GraphScope,
		trustedProxies: trusted,
		cookieSecure:   opts.CookieSecure,
		serveUI:        opts.ServeUI,
		metricsEnabled: opts.MetricsEnabled,
		metricsPath:    opts.MetricsPath,
		metrics:        opts.Metrics,
		log:            opts.Log,
	}
	s.handler = s.routes()
	return s, nil
}

// Handler returns the HTTP handler for the management interface.
func (s *Server) Handler() http.Handler { return s.handler }

// ServeHTTP lets the Server be used directly as a handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// routes builds the router.
//
// Every mutating route names the permission it needs. The authorization test
// walks this router and fails on any route it does not have an expectation for,
// so a new endpoint cannot be added without deciding who may call it.
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()

	r.Use(s.withRequestID)
	r.Use(s.recoverPanics)
	r.Use(s.logRequests)
	r.Use(securityHeaders)

	// Liveness and readiness are deliberately unauthenticated: a probe has no
	// credentials, and neither reveals anything about the deployment.
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)

	if s.metricsEnabled {
		r.Handle(s.metricsPath, s.metricsHandler())
	}

	r.Route("/api/v1", func(api chi.Router) {
		api.Use(noCache)

		// Sign-in has to be reachable without a session.
		api.Route("/auth", func(auth chi.Router) {
			auth.Get("/config", s.handleAuthConfig)
			auth.Post("/login", s.handleLogin)
			auth.Get("/oidc/start", s.handleOIDCStart)
			auth.Get("/oidc/callback", s.handleOIDCCallback)

			// Signing out needs a session but no particular permission.
			auth.Group(func(inner chi.Router) {
				inner.Use(s.requireSession)
				inner.Post("/logout", s.handleLogout)
				inner.Get("/me", s.handleMe)
				inner.Post("/password", s.handleChangeOwnPassword)
			})
		})

		api.Group(func(private chi.Router) {
			private.Use(s.requireSession)

			private.Route("/status", func(sr chi.Router) {
				sr.Use(s.require(adminauth.PermViewStatus))
				sr.Get("/", s.handleStatus)
			})

			s.mountCredentials(private)
			s.mountMailboxes(private)
			s.mountAccounts(private)
			s.mountMessages(private)
			s.mountUsers(private)
			s.mountAudit(private)
		})

		// Anything under /api that did not match is a client error, not the UI.
		api.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusNotFound, CodeNotFound, "no such endpoint")
		})
		api.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusMethodNotAllowed, CodeBadRequest, "that method is not allowed here")
		})
	})

	if s.serveUI {
		r.NotFound(webui.Handler().ServeHTTP)
	}
	return r
}

// handleHealthz reports that the process is running.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports whether the proxy can serve.
//
// It checks the database, because a proxy that cannot reach its queue cannot
// accept mail either, and a load balancer should stop sending it traffic.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	if err := s.db.PingContext(ctx); err != nil {
		s.logger(r).Warn("readiness check failed", "reason", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"reason": "the database is not reachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
