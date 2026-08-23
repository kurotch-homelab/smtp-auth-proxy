// Package config loads and validates the static configuration the process
// needs at startup: listeners, TLS, database, encryption keys and admin
// settings. Everything an operator changes at runtime — mailboxes, OAuth
// credentials, SMTP accounts — lives in the database instead, and is managed
// through the admin UI or seeded from a bootstrap file.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole configuration file.
type Config struct {
	Log        Log        `yaml:"log"`
	Database   Database   `yaml:"database"`
	Encryption Encryption `yaml:"encryption"`
	Storage    Storage    `yaml:"storage"`
	SMTP       SMTP       `yaml:"smtp"`
	Queue      Queue      `yaml:"queue"`
	Upstream   Upstream   `yaml:"upstream"`
	Admin      Admin      `yaml:"admin"`
	Bootstrap  Bootstrap  `yaml:"bootstrap"`
}

// Log controls diagnostic output.
type Log struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level"`
	// Format is json or text.
	Format string `yaml:"format"`
	// IncludeSubjects records message subjects in logs and the queue UI. Subjects
	// can carry personal data, so this defaults to off.
	IncludeSubjects bool `yaml:"include_subjects"`
}

// Database selects the backing store.
type Database struct {
	// Driver is sqlite or postgres.
	Driver string `yaml:"driver"`
	// DSN is a file path for sqlite, or a postgres:// URL.
	DSN string `yaml:"dsn"`
	// MaxOpenConns caps the pool. 0 means unlimited (and is ignored by sqlite,
	// which is always serialized to a single writer).
	MaxOpenConns int `yaml:"max_open_conns"`
	MaxIdleConns int `yaml:"max_idle_conns"`
	// ConnMaxLifetime recycles connections, which matters behind a pooler.
	ConnMaxLifetime Duration `yaml:"conn_max_lifetime"`
	// AutoMigrate applies pending migrations at startup.
	AutoMigrate bool `yaml:"auto_migrate"`
}

// Encryption holds the keys that protect secrets at rest.
type Encryption struct {
	// Keys are "<id>:<base64 32 bytes>" specifications. The first is used for
	// new ciphertexts; the rest are kept so values sealed with a retired key
	// remain readable during rotation.
	Keys []string `yaml:"keys"`
}

// Storage decides where message bodies live.
type Storage struct {
	// Blob is db or fs. db keeps everything in one place and lets several
	// replicas share a Postgres backend without a shared volume; fs keeps large
	// messages out of the database at the cost of needing that shared volume.
	Blob string `yaml:"blob"`
	// SpoolDir is used when Blob is fs.
	SpoolDir string `yaml:"spool_dir"`
	// MaxMessageSize rejects oversized submissions at DATA time. Exchange Online
	// caps a message at 150MB but shrinks that after MIME encoding; 35MB matches
	// the default mailbox send limit.
	MaxMessageSize ByteSize `yaml:"max_message_size"`
}

// SMTP configures the LAN-facing listeners.
type SMTP struct {
	// Hostname is announced in the EHLO banner and used in Received headers.
	Hostname  string     `yaml:"hostname"`
	Listeners []Listener `yaml:"listeners"`
	TLS       TLS        `yaml:"tls"`
	// AllowInsecureAuth permits AUTH on a connection that is not encrypted. It
	// exists for devices with no TLS support at all, and it means their password
	// crosses the network in the clear.
	AllowInsecureAuth bool `yaml:"allow_insecure_auth"`

	MaxRecipients       int `yaml:"max_recipients"`
	MaxConnections      int `yaml:"max_connections"`
	MaxConnectionsPerIP int `yaml:"max_connections_per_ip"`
	// MaxAuthFailures closes a connection after this many failed AUTH attempts.
	MaxAuthFailures int `yaml:"max_auth_failures"`

	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`

	ProxyProtocol ProxyProtocol `yaml:"proxy_protocol"`
}

// Listener is one bound SMTP socket.
type Listener struct {
	Address string `yaml:"address"`
	// TLS is none, starttls or implicit.
	TLS string `yaml:"tls"`
	// RequireTLS refuses MAIL FROM until the connection is encrypted.
	RequireTLS bool `yaml:"require_tls"`
	// RequireAuth refuses unauthenticated submission. There is no open-relay
	// mode; this exists only so a listener can be made auth-optional for a
	// health check.
	RequireAuth bool `yaml:"require_auth"`
}

// TLS points at the certificate served to LAN clients.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// SelfSigned generates an in-memory certificate at startup. Useful for a
	// first run or a test lab; every client will have to be told to trust it.
	SelfSigned bool `yaml:"self_signed"`
	// MinVersion is 1.2 or 1.3. Old printers routinely cannot do 1.3.
	MinVersion string `yaml:"min_version"`
}

// ProxyProtocol recovers the real client address behind a TCP load balancer.
type ProxyProtocol struct {
	Enabled bool `yaml:"enabled"`
	// TrustedNetworks are the CIDRs allowed to send a PROXY header. Accepting
	// one from an untrusted peer would let any client forge its source address
	// and defeat per-account CIDR restrictions.
	TrustedNetworks []string `yaml:"trusted_networks"`
}

// Queue configures the delivery workers.
type Queue struct {
	// Workers is the number of messages delivered concurrently across all
	// mailboxes. Per-mailbox concurrency is capped separately.
	Workers int   `yaml:"workers"`
	Retry   Retry `yaml:"retry"`
	// LeaseDuration is how long a worker owns a message before another replica
	// may reclaim it. It must comfortably exceed the upstream timeout.
	LeaseDuration Duration `yaml:"lease_duration"`
	// PollInterval is how often a worker looks for new work when idle.
	PollInterval Duration `yaml:"poll_interval"`

	// DefaultRateLimitPerMin and DefaultMaxConcurrent apply to mailboxes that do
	// not override them. Exchange Online allows 30 messages/minute and 3
	// concurrent connections per mailbox; staying under those avoids
	// "4.7.500 Server busy".
	DefaultRateLimitPerMin int `yaml:"default_rate_limit_per_min"`
	DefaultMaxConcurrent   int `yaml:"default_max_concurrent"`

	Retention Retention `yaml:"retention"`
}

// Retry controls redelivery of temporarily failed messages.
type Retry struct {
	MaxAttempts int `yaml:"max_attempts"`
	// MaxAge gives up on a message this long after it was accepted, even if
	// attempts remain.
	MaxAge Duration `yaml:"max_age"`
	// Backoff is the delay before each retry. The last entry repeats once the
	// list is exhausted.
	Backoff []Duration `yaml:"backoff"`
	// Jitter spreads retries so a batch queued together does not stampede.
	Jitter float64 `yaml:"jitter"`
}

// Retention prunes delivered and abandoned messages.
type Retention struct {
	Sent   Duration `yaml:"sent"`
	Failed Duration `yaml:"failed"`
	// PurgeInterval is how often the cleanup runs.
	PurgeInterval Duration `yaml:"purge_interval"`
}

// Upstream describes the Microsoft 365 endpoints. The defaults are correct for
// worldwide commercial tenants; sovereign clouds override them.
type Upstream struct {
	SMTP    UpstreamSMTP  `yaml:"smtp"`
	Graph   UpstreamGraph `yaml:"graph"`
	OAuth   UpstreamOAuth `yaml:"oauth"`
	Timeout Duration      `yaml:"timeout"`
}

// UpstreamSMTP is the Exchange Online submission endpoint.
type UpstreamSMTP struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// UpstreamGraph is the Microsoft Graph endpoint.
type UpstreamGraph struct {
	Endpoint string `yaml:"endpoint"`
}

// UpstreamOAuth is the Microsoft Entra token endpoint.
type UpstreamOAuth struct {
	// Authority is the login host, e.g. https://login.microsoftonline.com.
	Authority string `yaml:"authority"`
	// Scope must be https://outlook.office365.com/.default for SMTP AUTH and
	// https://graph.microsoft.com/.default for Graph. It is resolved per
	// transport; this is only the SMTP default.
	SMTPScope  string `yaml:"smtp_scope"`
	GraphScope string `yaml:"graph_scope"`
}

// Admin configures the management API and UI.
type Admin struct {
	Address string `yaml:"address"`
	// BaseURL is the externally reachable origin. It is required for OIDC,
	// which needs an exact redirect URI.
	BaseURL string    `yaml:"base_url"`
	TLS     AdminTLS  `yaml:"tls"`
	Session Session   `yaml:"session"`
	Local   LocalAuth `yaml:"local_auth"`
	OIDC    OIDC      `yaml:"oidc"`
	Metrics Metrics   `yaml:"metrics"`
	// TrustedProxies are the CIDRs whose X-Forwarded-For header is believed,
	// for audit logging and login rate limiting.
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// AdminTLS terminates HTTPS directly, for deployments without an ingress.
type AdminTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Session controls admin login sessions.
type Session struct {
	// Lifetime is the absolute cap on a session, regardless of activity.
	Lifetime Duration `yaml:"lifetime"`
	// IdleTimeout ends a session that has been unused for this long.
	IdleTimeout Duration `yaml:"idle_timeout"`
	// CookieSecure is auto, true or false. auto sets the Secure attribute when
	// BaseURL is https, which is what a reverse-proxy deployment needs.
	CookieSecure string `yaml:"cookie_secure"`
	CookieName   string `yaml:"cookie_name"`
}

// LocalAuth configures username and password login.
type LocalAuth struct {
	Enabled bool    `yaml:"enabled"`
	Lockout Lockout `yaml:"lockout"`
	// RequireTOTP forces every local user to enroll a second factor.
	RequireTOTP bool `yaml:"require_totp"`
}

// Lockout throttles password guessing.
type Lockout struct {
	Threshold int      `yaml:"threshold"`
	Duration  Duration `yaml:"duration"`
}

// OIDC configures single sign-on.
type OIDC struct {
	Enabled      bool     `yaml:"enabled"`
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
	// RoleClaim is the ID token claim inspected for role mapping, e.g. groups.
	RoleClaim string `yaml:"role_claim"`
	// RoleMappings maps a claim value to a role. Values are matched exactly.
	RoleMappings map[string]string `yaml:"role_mappings"`
	// DefaultRole is assigned when no mapping matches. Empty denies the login,
	// which is the safe default for a tenant-wide identity provider.
	DefaultRole string `yaml:"default_role"`
	// UsernameClaim identifies the user, e.g. preferred_username or email.
	UsernameClaim string `yaml:"username_claim"`
	// AllowSignup provisions an account on first successful login.
	AllowSignup bool `yaml:"allow_signup"`
}

// Metrics exposes Prometheus metrics.
type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// Bootstrap seeds mailboxes, credentials and SMTP accounts from a file.
type Bootstrap struct {
	// Mode is off, apply-once or reconcile.
	//
	// apply-once inserts anything missing and then leaves the database alone,
	// so the admin UI stays authoritative. reconcile re-applies the file on
	// every start and marks the declared objects read-only in the UI, which is
	// what a GitOps deployment wants.
	Mode string `yaml:"mode"`
	Path string `yaml:"path"`
}

// Defaults returns a configuration that runs sensibly with an empty file
// except for the values that cannot be guessed: the encryption key and,
// for a real deployment, the TLS certificate.
func Defaults() Config {
	return Config{
		Log: Log{Level: "info", Format: "json"},
		Database: Database{
			Driver:          DriverSQLite,
			DSN:             "/var/lib/smtp-auth-proxy/data.db",
			MaxOpenConns:    0,
			MaxIdleConns:    2,
			ConnMaxLifetime: Duration(time.Hour),
			AutoMigrate:     true,
		},
		Storage: Storage{
			Blob:           BlobDB,
			SpoolDir:       "/var/lib/smtp-auth-proxy/spool",
			MaxMessageSize: 35 << 20,
		},
		SMTP: SMTP{
			Hostname: "smtp-auth-proxy",
			Listeners: []Listener{
				{Address: ":587", TLS: TLSStartTLS, RequireTLS: true, RequireAuth: true},
			},
			TLS:                 TLS{MinVersion: "1.2"},
			MaxRecipients:       100,
			MaxConnections:      100,
			MaxConnectionsPerIP: 10,
			MaxAuthFailures:     5,
			ReadTimeout:         Duration(5 * time.Minute),
			WriteTimeout:        Duration(5 * time.Minute),
		},
		Queue: Queue{
			Workers:       4,
			LeaseDuration: Duration(5 * time.Minute),
			PollInterval:  Duration(5 * time.Second),
			Retry: Retry{
				MaxAttempts: 12,
				MaxAge:      Duration(72 * time.Hour),
				Backoff: []Duration{
					Duration(time.Minute),
					Duration(5 * time.Minute),
					Duration(15 * time.Minute),
					Duration(time.Hour),
					Duration(4 * time.Hour),
					Duration(12 * time.Hour),
				},
				Jitter: 0.2,
			},
			DefaultRateLimitPerMin: 30,
			DefaultMaxConcurrent:   2,
			Retention: Retention{
				Sent:          Duration(30 * 24 * time.Hour),
				Failed:        Duration(30 * 24 * time.Hour),
				PurgeInterval: Duration(time.Hour),
			},
		},
		Upstream: Upstream{
			SMTP:  UpstreamSMTP{Host: "smtp.office365.com", Port: 587},
			Graph: UpstreamGraph{Endpoint: "https://graph.microsoft.com"},
			OAuth: UpstreamOAuth{
				Authority:  "https://login.microsoftonline.com",
				SMTPScope:  "https://outlook.office365.com/.default",
				GraphScope: "https://graph.microsoft.com/.default",
			},
			Timeout: Duration(2 * time.Minute),
		},
		Admin: Admin{
			Address: ":8080",
			Session: Session{
				Lifetime:     Duration(12 * time.Hour),
				IdleTimeout:  Duration(time.Hour),
				CookieSecure: "auto",
				CookieName:   "sap_session",
			},
			Local: LocalAuth{
				Enabled: true,
				Lockout: Lockout{Threshold: 5, Duration: Duration(15 * time.Minute)},
			},
			OIDC: OIDC{
				Scopes:        []string{"openid", "profile", "email"},
				RoleClaim:     "groups",
				UsernameClaim: "preferred_username",
			},
			Metrics: Metrics{Enabled: true, Path: "/metrics"},
		},
		Bootstrap: Bootstrap{Mode: BootstrapOff, Path: ""},
	}
}

// Load reads, expands and validates a configuration file.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: reading %s: %w", path, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Parse expands variables in a configuration document, decodes it over the
// defaults and validates the result.
func Parse(raw []byte) (Config, error) {
	expanded, err := Expand(string(raw))
	if err != nil {
		return Config{}, err
	}

	cfg := Defaults()
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	// Reject unknown keys: a typo in a key name would otherwise be silently
	// ignored and leave the operator with a setting that never took effect.
	dec.KnownFields(true)
	// An empty or comment-only document decodes to io.EOF, which is not an
	// error: it simply means every value comes from the defaults.
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parsing YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
