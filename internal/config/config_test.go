package config

import (
	"errors"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// testEncryptionKey is a throwaway all-zero key; it only has to be well-formed.
const testEncryptionKey = "k1:0000000000000000000000000000000000000000000="

// minimalYAML is the smallest document that validates on its own: everything
// else comes from Defaults().
const minimalYAML = `
encryption:
  keys: ["` + testEncryptionKey + `"]
smtp:
  tls:
    self_signed: true
`

// parseOverlay decodes doc over a configuration that already has an encryption
// key and a usable TLS setup, so each table case only has to state the field it
// is actually testing. Concatenating YAML fragments instead would produce
// duplicate top-level keys.
func parseOverlay(doc string) (Config, error) {
	expanded, err := Expand(doc)
	if err != nil {
		return Config{}, err
	}

	cfg := Defaults()
	cfg.Encryption.Keys = []string{testEncryptionKey}
	cfg.SMTP.TLS.SelfSigned = true

	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && err.Error() != "EOF" {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseOK(t *testing.T, doc string) Config {
	t.Helper()
	cfg, err := parseOverlay(doc)
	if err != nil {
		t.Fatalf("parse:\n%v", err)
	}
	return cfg
}

func parseErr(t *testing.T, doc string) error {
	t.Helper()
	cfg, err := parseOverlay(doc)
	if err == nil {
		t.Fatalf("parse succeeded, want an error (got %+v)", cfg.Log)
	}
	return err
}

func TestParseMinimalDocumentUsesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse:\n%v", err)
	}
	def := Defaults()

	if cfg.Log.Level != def.Log.Level {
		t.Errorf("log.level = %q, want the default %q", cfg.Log.Level, def.Log.Level)
	}
	if cfg.Database.Driver != DriverSQLite {
		t.Errorf("database.driver = %q, want sqlite", cfg.Database.Driver)
	}
	if len(cfg.SMTP.Listeners) != 1 || cfg.SMTP.Listeners[0].Address != ":587" {
		t.Errorf("smtp.listeners = %+v, want a single :587 listener", cfg.SMTP.Listeners)
	}
	// The Exchange Online limits must be the defaults, not something looser.
	if cfg.Queue.DefaultRateLimitPerMin != 30 {
		t.Errorf("queue.default_rate_limit_per_min = %d, want 30", cfg.Queue.DefaultRateLimitPerMin)
	}
	if cfg.Queue.DefaultMaxConcurrent != 2 {
		t.Errorf("queue.default_max_concurrent = %d, want 2 (Exchange allows 3)", cfg.Queue.DefaultMaxConcurrent)
	}
	if cfg.Upstream.OAuth.SMTPScope != "https://outlook.office365.com/.default" {
		t.Errorf("upstream.oauth.smtp_scope = %q, want the Exchange Online scope", cfg.Upstream.OAuth.SMTPScope)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	// A typo must fail loudly; silently ignoring it leaves an operator with a
	// setting that never took effect.
	_, err := Parse([]byte(minimalYAML + `
log:
  levl: debug
`))
	if err == nil {
		t.Fatal("Parse accepted an unknown field")
	}
	if !strings.Contains(err.Error(), "levl") {
		t.Errorf("error should name the unknown field, got: %v", err)
	}
}

func TestParseExampleConfig(t *testing.T) {
	// Not parallel: sets environment variables the example file references.
	t.Setenv("SMTP_AUTH_PROXY_ENCRYPTION_KEY", "k1:0000000000000000000000000000000000000000000=")

	raw, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatalf("reading the shipped example config: %v", err)
	}
	// The example ships a cert path that does not exist here, which is fine:
	// Validate only checks that the pair is set, not that the files are present.
	if _, err := Parse(raw); err != nil {
		t.Fatalf("the shipped config.example.yaml does not validate:\n%v", err)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`
log:
  level: verbose
  format: xml
database:
  driver: mysql
encryption:
  keys: []
`))
	if err == nil {
		t.Fatal("Parse accepted an invalid document")
	}
	// Reporting one problem per restart makes fixing a config file miserable.
	for _, want := range []string{"log.level", "log.format", "database.driver", "encryption.keys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got:\n%v", want, err)
		}
	}
}

func TestValidateRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "listener without auth would be an open relay",
			doc: `
smtp:
  listeners:
    - address: ":587"
      tls: starttls
      require_auth: false
`,
			want: "open relay",
		},
		{
			name: "require_tls with tls none is contradictory",
			doc: `
smtp:
  listeners:
    - address: ":25"
      tls: none
      require_tls: true
      require_auth: true
`,
			want: "can never be encrypted",
		},
		{
			name: "duplicate listener address",
			doc: `
smtp:
  listeners:
    - address: ":587"
      tls: starttls
      require_auth: true
    - address: ":587"
      tls: starttls
      require_auth: true
`,
			want: "already used by",
		},
		{
			name: "address without a port",
			doc: `
smtp:
  listeners:
    - address: "587"
      tls: starttls
      require_auth: true
`,
			want: "is not host:port",
		},
		{
			name: "tls listener with no certificate",
			doc: `
smtp:
  tls:
    self_signed: false
`,
			want: "no cert_file/key_file is configured",
		},
		{
			name: "cert without key",
			doc: `
smtp:
  tls:
    self_signed: false
    cert_file: /tls/tls.crt
`,
			want: "must be set together",
		},
		{
			name: "cert files and self_signed together",
			doc: `
smtp:
  tls:
    cert_file: /tls/tls.crt
    key_file: /tls/tls.key
    self_signed: true
`,
			want: "not both",
		},
		{
			name: "concurrency above the Exchange limit",
			doc: `
queue:
  default_max_concurrent: 8
`,
			want: "3 concurrent connections",
		},
		{
			name: "rate above the Exchange limit",
			doc: `
queue:
  default_rate_limit_per_min: 600
`,
			want: "30 messages/minute",
		},
		{
			name: "lease shorter than the upstream timeout",
			doc: `
queue:
  lease_duration: 30s
upstream:
  timeout: 2m
`,
			want: "must exceed upstream.timeout",
		},
		{
			name: "proxy protocol without trusted networks",
			doc: `
smtp:
  proxy_protocol:
    enabled: true
`,
			want: "trusted_networks",
		},
		{
			name: "malformed CIDR",
			doc: `
admin:
  trusted_proxies: ["10.0.0.1"]
`,
			want: "is not a CIDR",
		},
		{
			name: "no way to sign in",
			doc: `
admin:
  local_auth:
    enabled: false
  oidc:
    enabled: false
`,
			want: "nobody could sign in",
		},
		{
			name: "idle timeout longer than session lifetime",
			doc: `
admin:
  session:
    lifetime: 1h
    idle_timeout: 2h
`,
			want: "must not exceed",
		},
		{
			name: "bootstrap mode without a path",
			doc: `
bootstrap:
  mode: reconcile
`,
			want: "bootstrap.path",
		},
		{
			name: "postgres driver with a file DSN",
			doc: `
database:
  driver: postgres
  dsn: /var/lib/data.db
`,
			want: "postgres:// URL",
		},
		{
			name: "relative sqlite path",
			doc: `
database:
  driver: sqlite
  dsn: data.db
`,
			want: "absolute path",
		},
		{
			name: "graph endpoint must be https",
			doc: `
upstream:
  graph:
    endpoint: http://graph.microsoft.com
`,
			want: "must use https",
		},
		{
			name: "encryption key without an id",
			doc: `
encryption:
  keys: ["justthekey"]
`,
			want: "<id>:<base64 key>",
		},
		{
			name: "encryption key that failed to expand",
			doc: `
encryption:
  keys: ["${MISSING_KEY:-}"]
`,
			want: "environment variable fail to expand",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := parseErr(t, tt.doc)
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should mention %q, got:\n%v", tt.want, err)
			}
		})
	}
}

func TestValidateOIDC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "enabled with nothing configured",
			doc: `
admin:
  oidc:
    enabled: true
`,
			want: "client_id",
		},
		{
			name: "missing base_url",
			doc: `
admin:
  base_url: ""
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
    default_role: viewer
`,
			want: "admin.base_url",
		},
		{
			name: "scopes without openid",
			doc: `
admin:
  base_url: https://admin.example.com
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
    scopes: [profile]
    default_role: viewer
`,
			want: `must include "openid"`,
		},
		{
			name: "unknown role in a mapping",
			doc: `
admin:
  base_url: https://admin.example.com
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
    role_mappings:
      group-a: superuser
`,
			want: "is not a valid role",
		},
		{
			name: "no mappings and no default denies everyone",
			doc: `
admin:
  base_url: https://admin.example.com
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
`,
			want: "every SSO login would be denied",
		},
		{
			name: "role_mappings without role_claim",
			doc: `
admin:
  base_url: https://admin.example.com
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
    role_claim: ""
    role_mappings:
      group-a: admin
`,
			want: "role_claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := parseErr(t, tt.doc)
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should mention %q, got:\n%v", tt.want, err)
			}
		})
	}
}

func TestValidOIDCConfigurationIsAccepted(t *testing.T) {
	t.Parallel()

	cfg := parseOK(t, `
admin:
  base_url: https://admin.example.com
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
    role_claim: groups
    role_mappings:
      sre: admin
      helpdesk: operator
    default_role: viewer
`)
	if got := cfg.Admin.OIDC.RoleMappings["sre"]; got != RoleAdmin {
		t.Errorf("role mapping for sre = %q, want admin", got)
	}
}

func TestWarnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "plaintext auth",
			doc: `
smtp:
  allow_insecure_auth: true
`,
			want: "plaintext",
		},
		{
			name: "starttls offered but not required",
			doc: `
smtp:
  listeners:
    - address: ":587"
      tls: starttls
      require_tls: false
      require_auth: true
`,
			want: "does not require it",
		},
		{
			name: "self-signed certificate",
			doc:  ``, // minimalYAML already sets self_signed
			want: "not suitable for production",
		},
		{
			name: "sqlite with a filesystem spool",
			doc: `
storage:
  blob: fs
`,
			want: "cannot be scaled beyond one replica",
		},
		{
			name: "SSO signup straight to admin",
			doc: `
admin:
  base_url: https://admin.example.com
  oidc:
    enabled: true
    issuer: https://idp.example.com
    client_id: id
    client_secret: secret
    default_role: admin
    allow_signup: true
`,
			want: "gains full control",
		},
		{
			name: "insecure base URL with a non-Secure cookie",
			doc: `
admin:
  base_url: http://admin.example.com
`,
			want: "not marked Secure",
		},
		{
			name: "subject logging",
			doc: `
log:
  include_subjects: true
`,
			want: "personal data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A warning must never stop the process from starting.
			cfg := parseOK(t, tt.doc)
			warnings := strings.Join(cfg.Warnings(), "\n")
			if !strings.Contains(warnings, tt.want) {
				t.Errorf("warnings should mention %q, got:\n%s", tt.want, warnings)
			}
		})
	}
}

func TestNoWarningsForASoundConfiguration(t *testing.T) {
	t.Parallel()

	cfg, err := Parse([]byte(`
encryption:
  keys: ["` + testEncryptionKey + `"]
smtp:
  tls:
    cert_file: /tls/tls.crt
    key_file: /tls/tls.key
admin:
  base_url: https://admin.example.com
`))
	if err != nil {
		t.Fatalf("Parse:\n%v", err)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("a sound configuration produced warnings: %v", w)
	}
}

func TestErrorsUnwrapExposesIndividualProblems(t *testing.T) {
	t.Parallel()

	err := parseErr(t, `
log:
  level: verbose
`)
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("Validate returned %T, want config.Errors", err)
	}
	if len(errs) == 0 {
		t.Fatal("Errors is empty")
	}
	if len(errs.Unwrap()) != len(errs) {
		t.Errorf("Unwrap returned %d problems, want %d", len(errs.Unwrap()), len(errs))
	}
}

func TestLoadReportsTheFilename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/config.yaml"
	if err := os.WriteFile(path, []byte("log:\n  level: nonsense\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load = nil error, want error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the file, got: %v", err)
	}

	if _, err := Load(dir + "/does-not-exist.yaml"); err == nil {
		t.Error("Load of a missing file = nil error, want error")
	}
}
