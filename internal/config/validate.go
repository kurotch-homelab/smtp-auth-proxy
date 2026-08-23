package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

// Enumerated configuration values.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"

	BlobDB = "db"
	BlobFS = "fs"

	TLSNone     = "none"
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"

	BootstrapOff       = "off"
	BootstrapApplyOnce = "apply-once"
	BootstrapReconcile = "reconcile"

	CookieSecureAuto = "auto"

	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var (
	validLogLevels     = []string{"debug", "info", "warn", "error"}
	validLogFormats    = []string{"json", "text"}
	validDrivers       = []string{DriverSQLite, DriverPostgres}
	validBlobModes     = []string{BlobDB, BlobFS}
	validListenerTLS   = []string{TLSNone, TLSStartTLS, TLSImplicit}
	validTLSVersions   = []string{"1.2", "1.3"}
	validBootstrapMode = []string{BootstrapOff, BootstrapApplyOnce, BootstrapReconcile}
	validCookieSecure  = []string{CookieSecureAuto, "true", "false"}
	validRoles         = []string{RoleAdmin, RoleOperator, RoleViewer}
)

// Errors is a collection of configuration problems. Reporting all of them at
// once means an operator fixes the file in one pass instead of restarting into
// the next complaint.
type Errors []error

func (e Errors) Error() string {
	msgs := make([]string, len(e))
	for i, err := range e {
		msgs[i] = "  - " + err.Error()
	}
	return fmt.Sprintf("%d configuration problem(s):\n%s", len(e), strings.Join(msgs, "\n"))
}

// Unwrap lets errors.Is and errors.As see through to the individual problems.
func (e Errors) Unwrap() []error { return e }

// validator accumulates problems while walking the configuration.
type validator struct{ errs Errors }

func (v *validator) add(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *validator) oneOf(field, value string, allowed []string) {
	if !slices.Contains(allowed, value) {
		v.add("%s: %q is not valid (expected one of: %s)", field, value, strings.Join(allowed, ", "))
	}
}

func (v *validator) positive(field string, value int) {
	if value <= 0 {
		v.add("%s: must be greater than 0, got %d", field, value)
	}
}

func (v *validator) positiveDuration(field string, value Duration) {
	if value.Duration() <= 0 {
		v.add("%s: must be greater than 0, got %s", field, value)
	}
}

// Validate reports every problem it can find, rather than stopping at the first.
func (c *Config) Validate() error {
	v := &validator{}

	c.validateLog(v)
	c.validateDatabase(v)
	c.validateEncryption(v)
	c.validateStorage(v)
	c.validateSMTP(v)
	c.validateQueue(v)
	c.validateUpstream(v)
	c.validateAdmin(v)
	c.validateBootstrap(v)

	if len(v.errs) > 0 {
		return v.errs
	}
	return nil
}

func (c *Config) validateLog(v *validator) {
	v.oneOf("log.level", c.Log.Level, validLogLevels)
	v.oneOf("log.format", c.Log.Format, validLogFormats)
}

func (c *Config) validateDatabase(v *validator) {
	v.oneOf("database.driver", c.Database.Driver, validDrivers)
	if c.Database.DSN == "" {
		v.add("database.dsn: must not be empty")
		return
	}

	switch c.Database.Driver {
	case DriverPostgres:
		u, err := url.Parse(c.Database.DSN)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			v.add("database.dsn: expected a postgres:// URL for driver postgres")
		}
	case DriverSQLite:
		// ":memory:" and "file:...:memory:" are legitimate in tests.
		if !strings.Contains(c.Database.DSN, ":memory:") && !filepath.IsAbs(c.Database.DSN) &&
			!strings.HasPrefix(c.Database.DSN, "file:") && !strings.HasPrefix(c.Database.DSN, "./") {
			v.add("database.dsn: %q should be an absolute path so it does not depend on the working directory", c.Database.DSN)
		}
	}

	if c.Database.MaxOpenConns < 0 {
		v.add("database.max_open_conns: must not be negative")
	}
	if c.Database.MaxIdleConns < 0 {
		v.add("database.max_idle_conns: must not be negative")
	}
}

func (c *Config) validateEncryption(v *validator) {
	if len(c.Encryption.Keys) == 0 {
		v.add("encryption.keys: at least one key is required; generate one with 'smtp-auth-proxy genkey'")
		return
	}
	for i, spec := range c.Encryption.Keys {
		if strings.TrimSpace(spec) == "" {
			v.add("encryption.keys[%d]: is empty (did an environment variable fail to expand?)", i)
			continue
		}
		if !strings.Contains(spec, ":") {
			v.add("encryption.keys[%d]: expected the form <id>:<base64 key>", i)
		}
	}
}

func (c *Config) validateStorage(v *validator) {
	v.oneOf("storage.blob", c.Storage.Blob, validBlobModes)
	if c.Storage.Blob == BlobFS && c.Storage.SpoolDir == "" {
		v.add("storage.spool_dir: required when storage.blob is fs")
	}
	if c.Storage.MaxMessageSize.Bytes() <= 0 {
		v.add("storage.max_message_size: must be greater than 0")
	}
}

func (c *Config) validateSMTP(v *validator) {
	if c.SMTP.Hostname == "" {
		v.add("smtp.hostname: must not be empty; it is announced in the EHLO banner")
	}
	if len(c.SMTP.Listeners) == 0 {
		v.add("smtp.listeners: at least one listener is required")
	}

	seen := make(map[string]int, len(c.SMTP.Listeners))
	needsCert := false
	for i, l := range c.SMTP.Listeners {
		field := fmt.Sprintf("smtp.listeners[%d]", i)
		if l.Address == "" {
			v.add("%s.address: must not be empty", field)
		} else {
			if _, _, err := net.SplitHostPort(l.Address); err != nil {
				v.add("%s.address: %q is not host:port", field, l.Address)
			}
			if prev, dup := seen[l.Address]; dup {
				v.add("%s.address: %q is already used by smtp.listeners[%d]", field, l.Address, prev)
			}
			seen[l.Address] = i
		}

		v.oneOf(field+".tls", l.TLS, validListenerTLS)
		if l.TLS != TLSNone {
			needsCert = true
		}
		if l.RequireTLS && l.TLS == TLSNone {
			v.add("%s: require_tls is set but tls is none, so the connection can never be encrypted", field)
		}
		if !l.RequireAuth {
			v.add("%s: require_auth is false, which would make this listener an open relay", field)
		}
	}

	c.validateSMTPTLS(v, needsCert)

	v.positive("smtp.max_recipients", c.SMTP.MaxRecipients)
	v.positive("smtp.max_connections", c.SMTP.MaxConnections)
	v.positive("smtp.max_connections_per_ip", c.SMTP.MaxConnectionsPerIP)
	v.positive("smtp.max_auth_failures", c.SMTP.MaxAuthFailures)
	v.positiveDuration("smtp.read_timeout", c.SMTP.ReadTimeout)
	v.positiveDuration("smtp.write_timeout", c.SMTP.WriteTimeout)

	if c.SMTP.ProxyProtocol.Enabled {
		if len(c.SMTP.ProxyProtocol.TrustedNetworks) == 0 {
			v.add("smtp.proxy_protocol.trusted_networks: required when proxy_protocol is enabled, " +
				"otherwise any client could forge its source address")
		}
		validateCIDRs(v, "smtp.proxy_protocol.trusted_networks", c.SMTP.ProxyProtocol.TrustedNetworks)
	}
}

func (c *Config) validateSMTPTLS(v *validator, needsCert bool) {
	t := c.SMTP.TLS
	v.oneOf("smtp.tls.min_version", t.MinVersion, validTLSVersions)

	hasFiles := t.CertFile != "" || t.KeyFile != ""
	switch {
	case hasFiles && t.SelfSigned:
		v.add("smtp.tls: set either cert_file/key_file or self_signed, not both")
	case (t.CertFile == "") != (t.KeyFile == ""):
		v.add("smtp.tls: cert_file and key_file must be set together")
	case needsCert && !hasFiles && !t.SelfSigned:
		v.add("smtp.tls: a listener uses TLS but no cert_file/key_file is configured " +
			"(set smtp.tls.self_signed: true for a test setup)")
	}
}

func (c *Config) validateQueue(v *validator) {
	v.positive("queue.workers", c.Queue.Workers)
	v.positive("queue.retry.max_attempts", c.Queue.Retry.MaxAttempts)
	v.positiveDuration("queue.retry.max_age", c.Queue.Retry.MaxAge)
	v.positiveDuration("queue.lease_duration", c.Queue.LeaseDuration)
	v.positiveDuration("queue.poll_interval", c.Queue.PollInterval)
	v.positive("queue.default_rate_limit_per_min", c.Queue.DefaultRateLimitPerMin)
	v.positive("queue.default_max_concurrent", c.Queue.DefaultMaxConcurrent)
	v.positiveDuration("queue.retention.purge_interval", c.Queue.Retention.PurgeInterval)

	if len(c.Queue.Retry.Backoff) == 0 {
		v.add("queue.retry.backoff: at least one delay is required")
	}
	for i, d := range c.Queue.Retry.Backoff {
		v.positiveDuration(fmt.Sprintf("queue.retry.backoff[%d]", i), d)
	}
	if c.Queue.Retry.Jitter < 0 || c.Queue.Retry.Jitter > 1 {
		v.add("queue.retry.jitter: must be between 0 and 1, got %v", c.Queue.Retry.Jitter)
	}

	// Exchange Online allows 3 concurrent SMTP submissions per mailbox. Using
	// all three leaves nothing for a retry and reliably produces "4.7.500".
	if c.Queue.DefaultMaxConcurrent > 3 {
		v.add("queue.default_max_concurrent: %d exceeds the 3 concurrent connections "+
			"Exchange Online allows per mailbox", c.Queue.DefaultMaxConcurrent)
	}
	if c.Queue.DefaultRateLimitPerMin > 30 {
		v.add("queue.default_rate_limit_per_min: %d exceeds the 30 messages/minute "+
			"Exchange Online allows per mailbox", c.Queue.DefaultRateLimitPerMin)
	}
	if c.Queue.LeaseDuration.Duration() <= c.Upstream.Timeout.Duration() {
		v.add("queue.lease_duration (%s) must exceed upstream.timeout (%s), "+
			"or a second replica could start delivering a message that is still in flight",
			c.Queue.LeaseDuration, c.Upstream.Timeout)
	}
}

func (c *Config) validateUpstream(v *validator) {
	if c.Upstream.SMTP.Host == "" {
		v.add("upstream.smtp.host: must not be empty")
	}
	if c.Upstream.SMTP.Port <= 0 || c.Upstream.SMTP.Port > 65535 {
		v.add("upstream.smtp.port: %d is not a valid port", c.Upstream.SMTP.Port)
	}
	validateHTTPSURL(v, "upstream.graph.endpoint", c.Upstream.Graph.Endpoint, true)
	validateHTTPSURL(v, "upstream.oauth.authority", c.Upstream.OAuth.Authority, true)

	if c.Upstream.OAuth.SMTPScope == "" {
		v.add("upstream.oauth.smtp_scope: must not be empty " +
			"(Exchange Online requires https://outlook.office365.com/.default)")
	}
	if c.Upstream.OAuth.GraphScope == "" {
		v.add("upstream.oauth.graph_scope: must not be empty")
	}
	v.positiveDuration("upstream.timeout", c.Upstream.Timeout)
}

func (c *Config) validateAdmin(v *validator) {
	if _, _, err := net.SplitHostPort(c.Admin.Address); err != nil {
		v.add("admin.address: %q is not host:port", c.Admin.Address)
	}
	if c.Admin.BaseURL != "" {
		validateHTTPSURL(v, "admin.base_url", c.Admin.BaseURL, false)
	}

	a := c.Admin.TLS
	if (a.CertFile == "") != (a.KeyFile == "") {
		v.add("admin.tls: cert_file and key_file must be set together")
	}

	v.positiveDuration("admin.session.lifetime", c.Admin.Session.Lifetime)
	v.positiveDuration("admin.session.idle_timeout", c.Admin.Session.IdleTimeout)
	if c.Admin.Session.IdleTimeout.Duration() > c.Admin.Session.Lifetime.Duration() {
		v.add("admin.session.idle_timeout (%s) must not exceed admin.session.lifetime (%s)",
			c.Admin.Session.IdleTimeout, c.Admin.Session.Lifetime)
	}
	v.oneOf("admin.session.cookie_secure", c.Admin.Session.CookieSecure, validCookieSecure)
	if c.Admin.Session.CookieName == "" {
		v.add("admin.session.cookie_name: must not be empty")
	}

	if c.Admin.Local.Enabled {
		v.positive("admin.local_auth.lockout.threshold", c.Admin.Local.Lockout.Threshold)
		v.positiveDuration("admin.local_auth.lockout.duration", c.Admin.Local.Lockout.Duration)
	}
	if !c.Admin.Local.Enabled && !c.Admin.OIDC.Enabled {
		v.add("admin: both local_auth and oidc are disabled, so nobody could sign in")
	}

	c.validateOIDC(v)

	if c.Admin.Metrics.Enabled && !strings.HasPrefix(c.Admin.Metrics.Path, "/") {
		v.add("admin.metrics.path: must start with '/'")
	}
	validateCIDRs(v, "admin.trusted_proxies", c.Admin.TrustedProxies)
}

func (c *Config) validateOIDC(v *validator) {
	o := c.Admin.OIDC
	if !o.Enabled {
		return
	}

	validateHTTPSURL(v, "admin.oidc.issuer", o.Issuer, true)
	if o.ClientID == "" {
		v.add("admin.oidc.client_id: required when oidc is enabled")
	}
	if o.ClientSecret == "" {
		v.add("admin.oidc.client_secret: required when oidc is enabled")
	}
	if c.Admin.BaseURL == "" {
		v.add("admin.base_url: required when oidc is enabled; it forms the redirect URI")
	}
	if !slices.Contains(o.Scopes, "openid") {
		v.add("admin.oidc.scopes: must include \"openid\"")
	}
	if o.UsernameClaim == "" {
		v.add("admin.oidc.username_claim: must not be empty")
	}

	if o.DefaultRole != "" {
		v.oneOf("admin.oidc.default_role", o.DefaultRole, validRoles)
	}
	for claim, role := range o.RoleMappings {
		if !slices.Contains(validRoles, role) {
			v.add("admin.oidc.role_mappings[%q]: %q is not a valid role (expected one of: %s)",
				claim, role, strings.Join(validRoles, ", "))
		}
	}
	if len(o.RoleMappings) > 0 && o.RoleClaim == "" {
		v.add("admin.oidc.role_claim: required when role_mappings is set")
	}
	if len(o.RoleMappings) == 0 && o.DefaultRole == "" {
		v.add("admin.oidc: no role_mappings and no default_role, so every SSO login would be denied")
	}
}

func (c *Config) validateBootstrap(v *validator) {
	v.oneOf("bootstrap.mode", c.Bootstrap.Mode, validBootstrapMode)
	if c.Bootstrap.Mode != BootstrapOff && c.Bootstrap.Path == "" {
		v.add("bootstrap.path: required when bootstrap.mode is %q", c.Bootstrap.Mode)
	}
}

func validateHTTPSURL(v *validator, field, raw string, requireHTTPS bool) {
	if raw == "" {
		v.add("%s: must not be empty", field)
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		v.add("%s: %q is not a valid URL", field, raw)
		return
	}
	switch {
	case u.Host == "":
		v.add("%s: %q has no host", field, raw)
	case requireHTTPS && u.Scheme != "https":
		v.add("%s: %q must use https", field, raw)
	case !requireHTTPS && u.Scheme != "http" && u.Scheme != "https":
		v.add("%s: %q must use http or https", field, raw)
	}
}

func validateCIDRs(v *validator, field string, cidrs []string) {
	for i, c := range cidrs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			v.add("%s[%d]: %q is not a CIDR (for a single address use /32 or /128)", field, i, c)
		}
	}
}

// Warnings returns configurations that are legal but worth saying out loud at
// startup. They never prevent the process from running — an operator who has
// decided to accept the risk should not have to fight the config loader — but
// they are logged at warn level every time.
func (c *Config) Warnings() []string {
	var w []string

	if c.SMTP.AllowInsecureAuth {
		w = append(w, "smtp.allow_insecure_auth is enabled: SMTP passwords will cross the network in plaintext")
	}
	for i, l := range c.SMTP.Listeners {
		if l.TLS != TLSNone && !l.RequireTLS {
			w = append(w, fmt.Sprintf(
				"smtp.listeners[%d] (%s) offers STARTTLS but does not require it: a client that skips it sends its password in plaintext",
				i, l.Address))
		}
	}
	if c.SMTP.TLS.SelfSigned {
		w = append(w, "smtp.tls.self_signed is enabled: every client must be configured to trust this certificate, so it is not suitable for production")
	}
	if c.Database.Driver == DriverSQLite && c.Storage.Blob == BlobFS {
		w = append(w, "storage.blob is fs with the sqlite driver: both the database and the spool are local files, so this deployment cannot be scaled beyond one replica")
	}
	if c.Admin.OIDC.Enabled && c.Admin.OIDC.AllowSignup && c.Admin.OIDC.DefaultRole == RoleAdmin {
		w = append(w, "admin.oidc grants every new single sign-on user the admin role: anyone your identity provider authenticates gains full control")
	}
	if c.Admin.BaseURL != "" && strings.HasPrefix(c.Admin.BaseURL, "http://") &&
		c.Admin.Session.CookieSecure != "true" {
		w = append(w, "admin.base_url is http:// so the session cookie is not marked Secure: the admin session token is exposed on the network")
	}
	if c.Log.IncludeSubjects {
		w = append(w, "log.include_subjects is enabled: message subjects, which may contain personal data, are written to the logs")
	}
	if c.Upstream.TLS.InsecureSkipVerify {
		w = append(w, "upstream.tls.insecure_skip_verify is enabled: the connection to Microsoft 365 is not verified, and the OAuth bearer token it carries is exposed to anyone on the network path")
	}

	return w
}
