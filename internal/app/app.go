// Package app assembles the proxy from its parts: configuration, database,
// encryption keys, token provider, transports, the SMTP front end and the
// delivery workers.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminapi"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/metrics"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/queue"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/smtpsrv"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport/graph"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport/smtprelay"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/version"
)

// App is a fully wired proxy.
type App struct {
	cfg config.Config
	log *slog.Logger

	db      *store.DB
	keyring *appcrypto.Keyring
	tokens  *oauth.Provider
	metrics *metrics.Metrics
	smtp    *smtpsrv.Server
	queue   *queue.Runner
	admin   *adminapi.Server
	// adminServer is the HTTP server for the management interface.
	adminServer *http.Server
}

// New builds an App from a validated configuration. It opens the database and
// applies migrations, but binds nothing until Run.
func New(ctx context.Context, cfg config.Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}

	keyring, err := appcrypto.NewKeyring(cfg.Encryption.Keys...)
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}

	db, err := store.Open(ctx, store.Options{
		Driver:          cfg.Database.Driver,
		DSN:             cfg.Database.DSN,
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime.Duration(),
	})
	if err != nil {
		return nil, err
	}

	if cfg.Database.AutoMigrate {
		applied, err := db.Migrate(ctx)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		if applied > 0 {
			log.Info("applied database migrations", "count", applied, "driver", cfg.Database.Driver)
		}
	}

	app := &App{cfg: cfg, log: log, db: db, keyring: keyring, metrics: metrics.New()}
	// Publish every known series at zero, so an alerting rule works before the
	// first failure rather than after it.
	app.metrics.Init([]string{string(store.TransportSMTP), string(store.TransportGraph)})

	if err := app.buildTokenProvider(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := app.buildSMTPServer(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := app.buildQueue(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := app.buildAdmin(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return app, nil
}

// buildAdmin assembles the management interface.
func (a *App) buildAdmin(ctx context.Context) error {
	sessions := adminauth.NewSessionManager(a.db, adminauth.SessionConfig{
		CookieName:  a.cfg.Admin.Session.CookieName,
		Lifetime:    a.cfg.Admin.Session.Lifetime.Duration(),
		IdleTimeout: a.cfg.Admin.Session.IdleTimeout.Duration(),
		Secure:      a.cookieSecure(),
	})

	var local *adminauth.LocalAuthenticator
	if a.cfg.Admin.Local.Enabled {
		local = adminauth.NewLocalAuthenticator(a.db, adminauth.LocalConfig{
			Enabled:          true,
			LockoutThreshold: a.cfg.Admin.Local.Lockout.Threshold,
			LockoutDuration:  a.cfg.Admin.Local.Lockout.Duration.Duration(),
		}, a.log)
	}

	oidcClient := &http.Client{Timeout: 30 * time.Second}
	oidcAuth, err := adminauth.NewOIDCAuthenticator(ctx, adminauth.OIDCConfig{
		Enabled:       a.cfg.Admin.OIDC.Enabled,
		Issuer:        a.cfg.Admin.OIDC.Issuer,
		ClientID:      a.cfg.Admin.OIDC.ClientID,
		ClientSecret:  a.cfg.Admin.OIDC.ClientSecret,
		Scopes:        a.cfg.Admin.OIDC.Scopes,
		BaseURL:       a.cfg.Admin.BaseURL,
		UsernameClaim: a.cfg.Admin.OIDC.UsernameClaim,
		RoleClaim:     a.cfg.Admin.OIDC.RoleClaim,
		RoleMappings:  a.cfg.Admin.OIDC.RoleMappings,
		DefaultRole:   a.cfg.Admin.OIDC.DefaultRole,
		AllowSignup:   a.cfg.Admin.OIDC.AllowSignup,
	}, a.db, oidcClient, a.log)
	if err != nil {
		return err
	}

	admin, err := adminapi.New(adminapi.Options{
		DB:             a.db,
		Keyring:        a.keyring,
		Sessions:       sessions,
		Local:          local,
		OIDC:           oidcAuth,
		OIDCClient:     oidcClient,
		Tokens:         a.tokens,
		SMTPScope:      a.cfg.Upstream.OAuth.SMTPScope,
		GraphScope:     a.cfg.Upstream.OAuth.GraphScope,
		TrustedProxies: a.cfg.Admin.TrustedProxies,
		CookieSecure:   a.cookieSecure(),
		MetricsEnabled: a.cfg.Admin.Metrics.Enabled,
		MetricsPath:    a.cfg.Admin.Metrics.Path,
		Metrics:        a.metrics,
		ServeUI:        true,
		Log:            a.log,
	})
	if err != nil {
		return err
	}

	a.admin = admin
	a.adminServer = &http.Server{
		Addr:    a.cfg.Admin.Address,
		Handler: admin,
		// The admin interface is behind a session; these bound how long a slow
		// or stalled client can hold a connection.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(a.log.Handler(), slog.LevelWarn),
	}
	return nil
}

// cookieSecure resolves the "auto" setting: a deployment reachable over https
// gets Secure cookies, and one that is not cannot have them without breaking
// sign-in entirely.
func (a *App) cookieSecure() bool {
	switch a.cfg.Admin.Session.CookieSecure {
	case "true":
		return true
	case "false":
		return false
	default:
		return strings.HasPrefix(a.cfg.Admin.BaseURL, "https://") ||
			a.cfg.Admin.TLS.CertFile != ""
	}
}

func (a *App) buildTokenProvider() error {
	tlsConfig, err := upstreamTLSConfig(a.cfg.Upstream.TLS)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: a.cfg.Upstream.Timeout.Duration()}
	if tlsConfig != nil {
		// Clone the default transport so the proxy keeps its connection
		// pooling and proxy-environment handling, and only the TLS settings
		// differ.
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return fmt.Errorf("app: the default HTTP transport is %T, not *http.Transport", http.DefaultTransport)
		}
		cloned := base.Clone()
		cloned.TLSClientConfig = tlsConfig
		client.Transport = cloned
	}

	// A credential may name its own authority; this is the default for the ones
	// that do not.
	opts := []oauth.ProviderOption{
		oauth.WithDefaultAuthorityHost(a.cfg.Upstream.OAuth.Authority),
	}

	// Instance discovery always reaches out to login.microsoftonline.com,
	// whatever authority a credential names. A deployment pointed at a private
	// endpoint cannot reach it, and would stall on every token request.
	if !strings.HasPrefix(a.cfg.Upstream.OAuth.Authority, oauth.DefaultAuthorityHost) {
		opts = append(opts, oauth.WithoutInstanceDiscovery())
		a.log.Info("instance discovery disabled for a non-default authority",
			"authority", a.cfg.Upstream.OAuth.Authority)
	}

	a.tokens = oauth.NewProvider(a.keyring, client, opts...)
	return nil
}

func (a *App) buildSMTPServer() error {
	tlsConfig, err := smtpsrv.BuildTLSConfig(a.cfg.SMTP.TLS)
	if err != nil {
		return err
	}

	server, err := smtpsrv.New(smtpsrv.Options{
		Hostname:            a.cfg.SMTP.Hostname,
		Listeners:           a.cfg.SMTP.Listeners,
		TLSConfig:           tlsConfig,
		MaxMessageBytes:     a.cfg.Storage.MaxMessageSize.Bytes(),
		MaxRecipients:       a.cfg.SMTP.MaxRecipients,
		MaxConnections:      a.cfg.SMTP.MaxConnections,
		MaxConnectionsPerIP: a.cfg.SMTP.MaxConnectionsPerIP,
		MaxAuthFailures:     a.cfg.SMTP.MaxAuthFailures,
		ReadTimeout:         a.cfg.SMTP.ReadTimeout.Duration(),
		WriteTimeout:        a.cfg.SMTP.WriteTimeout.Duration(),
		AllowInsecureAuth:   a.cfg.SMTP.AllowInsecureAuth,
		RecordSubjects:      a.cfg.Log.IncludeSubjects,
		ProxyProtocol:       a.cfg.SMTP.ProxyProtocol,
		Auth:                &authenticator{db: a.db, log: a.log},
		Submitter:           &submitter{db: a.db, log: a.log},
		Recorder:            recorder{m: a.metrics},
		Log:                 a.log,
	})
	if err != nil {
		return err
	}

	a.smtp = server
	return nil
}

func (a *App) buildQueue() error {
	upstreamTLS, err := upstreamTLSConfig(a.cfg.Upstream.TLS)
	if err != nil {
		return err
	}
	if upstreamTLS != nil {
		// Each transport needs the ServerName for its own endpoint.
		upstreamTLS = upstreamTLS.Clone()
		upstreamTLS.ServerName = a.cfg.Upstream.SMTP.Host
	}

	relay, err := smtprelay.New(smtprelay.Options{
		Host:      a.cfg.Upstream.SMTP.Host,
		Port:      a.cfg.Upstream.SMTP.Port,
		Scope:     a.cfg.Upstream.OAuth.SMTPScope,
		LocalName: a.cfg.SMTP.Hostname,
		Timeout:   a.cfg.Upstream.Timeout.Duration(),
		TLSConfig: upstreamTLS,
		Tokens:    a.tokens,
		Log:       a.log,
	})
	if err != nil {
		return err
	}

	delays := make([]time.Duration, 0, len(a.cfg.Queue.Retry.Backoff))
	for _, d := range a.cfg.Queue.Retry.Backoff {
		delays = append(delays, d.Duration())
	}

	graphTLS, err := upstreamTLSConfig(a.cfg.Upstream.TLS)
	if err != nil {
		return err
	}
	graphClient := &http.Client{Timeout: a.cfg.Upstream.Timeout.Duration()}
	if graphTLS != nil {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return fmt.Errorf("app: the default HTTP transport is %T, not *http.Transport", http.DefaultTransport)
		}
		cloned := base.Clone()
		cloned.TLSClientConfig = graphTLS
		graphClient.Transport = cloned
	}

	graphTransport, err := graph.New(graph.Options{
		Endpoint:   a.cfg.Upstream.Graph.Endpoint,
		Scope:      a.cfg.Upstream.OAuth.GraphScope,
		Timeout:    a.cfg.Upstream.Timeout.Duration(),
		HTTPClient: graphClient,
		Tokens:     a.tokens,
		Log:        a.log,
	})
	if err != nil {
		return err
	}

	runner, err := queue.New(queue.Options{
		DB: a.db,
		Transports: map[store.Transport]transport.Transport{
			store.TransportSMTP:  relay,
			store.TransportGraph: graphTransport,
		},
		Workers:       a.cfg.Queue.Workers,
		PollInterval:  a.cfg.Queue.PollInterval.Duration(),
		LeaseDuration: a.cfg.Queue.LeaseDuration.Duration(),
		Backoff: queue.Backoff{
			Delays:      delays,
			Jitter:      a.cfg.Queue.Retry.Jitter,
			MaxAttempts: a.cfg.Queue.Retry.MaxAttempts,
			MaxAge:      a.cfg.Queue.Retry.MaxAge.Duration(),
		},
		Budget: queue.Budget{
			PerMinute:     a.cfg.Queue.DefaultRateLimitPerMin,
			MaxConcurrent: a.cfg.Queue.DefaultMaxConcurrent,
		},
		RetainSent:    a.cfg.Queue.Retention.Sent.Duration(),
		RetainFailed:  a.cfg.Queue.Retention.Failed.Duration(),
		PurgeInterval: a.cfg.Queue.Retention.PurgeInterval.Duration(),
		WorkerID:      workerID(),
		Recorder:      recorder{m: a.metrics},
		Log:           a.log,
	})
	if err != nil {
		return err
	}

	a.queue = runner
	return nil
}

// workerID identifies this process in a message lease.
//
// Two replicas must never share one, or each could reclaim a message the other
// is still delivering. The hostname alone is not enough — a restarted pod keeps
// its name — so a random suffix is appended.
func workerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "worker"
	}
	return host + "-" + store.NewID()
}

// Run starts the SMTP listeners and the delivery workers, and blocks until ctx
// is done or something fails.
func (a *App) Run(ctx context.Context) error {
	a.log.Info("starting smtp-auth-proxy",
		"version", version.Get().Version,
		"driver", a.cfg.Database.Driver,
		"listeners", len(a.cfg.SMTP.Listeners))

	for _, w := range a.cfg.Warnings() {
		a.log.Warn(w)
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	record := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}

	// Both halves stop when either fails, so a proxy that cannot listen does
	// not sit there quietly draining its queue.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		record(a.smtp.Serve(runCtx))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		record(a.queue.Run(runCtx))
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		record(a.serveAdmin(runCtx))
	}()

	<-runCtx.Done()

	a.log.Info("shutting down")
	wg.Wait()
	return firstErr
}

// serveAdmin runs the management interface until ctx is done.
func (a *App) serveAdmin(ctx context.Context) error {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", a.cfg.Admin.Address)
	if err != nil {
		return fmt.Errorf("app: binding the admin interface on %s: %w", a.cfg.Admin.Address, err)
	}

	a.log.Info("admin interface started",
		"address", listener.Addr().String(),
		"tls", a.cfg.Admin.TLS.CertFile != "",
		"metrics", a.cfg.Admin.Metrics.Enabled)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), adminGracePeriod)
			defer cancel()
			_ = a.adminServer.Shutdown(shutdownCtx)
		case <-done:
		}
	}()

	if a.cfg.Admin.TLS.CertFile != "" {
		err = a.adminServer.ServeTLS(listener, a.cfg.Admin.TLS.CertFile, a.cfg.Admin.TLS.KeyFile)
	} else {
		err = a.adminServer.Serve(listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// adminGracePeriod bounds how long in-flight admin requests have to finish.
const adminGracePeriod = 15 * time.Second

// AdminAddress reports what the management interface bound to.
func (a *App) AdminAddress() string { return a.cfg.Admin.Address }

// Close releases the database.
func (a *App) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Close()
}

// DB exposes the store, for commands that operate on it directly.
func (a *App) DB() *store.DB { return a.db }

// SMTPAddresses reports what the SMTP listeners actually bound to, which
// matters when the configuration asked for port 0.
func (a *App) SMTPAddresses() []string { return a.smtp.Addresses() }

// Keyring exposes the encryption keys.
func (a *App) Keyring() *appcrypto.Keyring { return a.keyring }

// ErrNotConfigured is returned when a command needs something the
// configuration does not provide.
var ErrNotConfigured = errors.New("app: not configured")
