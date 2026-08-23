// Package bootstrap seeds credentials, mailboxes and SMTP accounts from a
// declarative file, so a deployment can be reproduced from a repository rather
// than from clicks.
//
// Two modes. apply-once creates whatever is missing on the first start and then
// leaves the database to the admin interface. reconcile reapplies the file on
// every start and marks the declared objects as bootstrap-managed, which makes
// them read-only in the admin interface — the file stays the source of truth.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// File is the bootstrap document.
type File struct {
	Credentials []Credential `yaml:"credentials"`
	Mailboxes   []Mailbox    `yaml:"mailboxes"`
	Accounts    []Account    `yaml:"accounts"`
}

// Credential declares a Microsoft Entra application registration.
type Credential struct {
	// Name identifies the credential; mailboxes reference it by this.
	Name     string `yaml:"name"`
	TenantID string `yaml:"tenant_id"`
	ClientID string `yaml:"client_id"`
	// AuthType is secret or certificate.
	AuthType string `yaml:"auth_type"`
	// ClientSecret supports ${ENV} and ${file:...} expansion, so the secret
	// itself lives in a Secret mount rather than in this file.
	ClientSecret string `yaml:"client_secret"`
	// CertificatePEM and CertificateKeyPEM likewise.
	CertificatePEM    string `yaml:"certificate_pem"`
	CertificateKeyPEM string `yaml:"certificate_key_pem"`
	AuthorityHost     string `yaml:"authority_host"`
}

// Mailbox declares a shared mailbox.
type Mailbox struct {
	Address     string `yaml:"address"`
	DisplayName string `yaml:"display_name"`
	// Credential is the Name of a credential in this file or already stored.
	Credential string `yaml:"credential"`
	// Transport is smtp or graph; empty means smtp.
	Transport       string `yaml:"transport"`
	RateLimitPerMin int    `yaml:"rate_limit_per_min"`
	MaxConcurrent   int    `yaml:"max_concurrent"`
	// Disabled inverts the stored Enabled flag; declaring something you do not
	// want active is rare, so the common case needs no key.
	Disabled bool `yaml:"disabled"`
}

// Account declares a device's SMTP credentials.
type Account struct {
	Username    string `yaml:"username"`
	Description string `yaml:"description"`
	// PasswordHash is an Argon2id PHC string, produced by `smtp-auth-proxy
	// passwd`. The file carries the hash, never the password.
	PasswordHash string `yaml:"password_hash"`
	// Mailboxes lists addresses this account may send as; the first is the
	// default unless DefaultMailbox names another.
	Mailboxes      []string `yaml:"mailboxes"`
	DefaultMailbox string   `yaml:"default_mailbox"`
	AllowedSenders []string `yaml:"allowed_senders"`
	// FromPolicy is reject, rewrite or passthrough; empty means reject.
	FromPolicy      string   `yaml:"from_policy"`
	AllowCIDRs      []string `yaml:"allow_cidrs"`
	RateLimitPerMin int      `yaml:"rate_limit_per_min"`
	Disabled        bool     `yaml:"disabled"`
}

// Load reads, expands and validates a bootstrap file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: reading %s: %w", path, err)
	}

	// The same ${ENV} and ${file:...} expansion as config.yaml, so secrets stay
	// out of the declarative file.
	expanded, err := config.Expand(string(raw))
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %s: %w", path, err)
	}

	var f File
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("bootstrap: parsing %s: %w", path, err)
	}

	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("bootstrap: %s: %w", path, err)
	}
	return &f, nil
}

// validate reports every problem at once, like the config loader does.
func (f *File) validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	credentialNames := map[string]bool{}
	for i := range f.Credentials {
		c := &f.Credentials[i]
		where := fmt.Sprintf("credentials[%d]", i)
		if c.Name == "" {
			add("%s: name is required", where)
		} else if credentialNames[c.Name] {
			add("%s: the name %q is declared twice", where, c.Name)
		}
		credentialNames[c.Name] = true

		if c.TenantID == "" {
			add("%s (%s): tenant_id is required", where, c.Name)
		}
		if c.ClientID == "" {
			add("%s (%s): client_id is required", where, c.Name)
		}
		switch c.AuthType {
		case "", "secret":
			if c.ClientSecret == "" {
				add("%s (%s): client_secret is required (use ${ENV} or ${file:...})", where, c.Name)
			}
		case "certificate":
			if c.CertificatePEM == "" || c.CertificateKeyPEM == "" {
				add("%s (%s): certificate_pem and certificate_key_pem are required", where, c.Name)
			}
		default:
			add("%s (%s): auth_type must be secret or certificate", where, c.Name)
		}
	}

	mailboxAddresses := map[string]bool{}
	for i, m := range f.Mailboxes {
		where := fmt.Sprintf("mailboxes[%d]", i)
		if m.Address == "" {
			add("%s: address is required", where)
			continue
		}
		normalized := strings.ToLower(m.Address)
		if mailboxAddresses[normalized] {
			add("%s: the address %q is declared twice", where, m.Address)
		}
		mailboxAddresses[normalized] = true

		if _, err := policy.ParseAddress(m.Address); err != nil {
			add("%s: %q is not a valid address", where, m.Address)
		}
		if m.Credential == "" {
			add("%s (%s): credential is required", where, m.Address)
		}
		switch m.Transport {
		case "", "smtp", "graph":
		default:
			add("%s (%s): transport must be smtp or graph", where, m.Address)
		}
		if m.RateLimitPerMin > 30 {
			add("%s (%s): rate_limit_per_min exceeds the 30/minute Exchange Online allows", where, m.Address)
		}
		if m.MaxConcurrent > 3 {
			add("%s (%s): max_concurrent exceeds the 3 connections Exchange Online allows", where, m.Address)
		}
	}

	usernames := map[string]bool{}
	for i := range f.Accounts {
		a := &f.Accounts[i]
		where := fmt.Sprintf("accounts[%d]", i)
		if a.Username == "" {
			add("%s: username is required", where)
			continue
		}
		if usernames[a.Username] {
			add("%s: the username %q is declared twice", where, a.Username)
		}
		usernames[a.Username] = true

		if a.PasswordHash == "" {
			add("%s (%s): password_hash is required; generate one with 'smtp-auth-proxy passwd'", where, a.Username)
		} else if !strings.HasPrefix(a.PasswordHash, "$argon2id$") {
			// The most likely mistake is putting the password itself here, and
			// silently hashing it would store the file's plaintext forever.
			add("%s (%s): password_hash is not an Argon2id hash; this field takes the output of 'smtp-auth-proxy passwd', never the password itself", where, a.Username)
		}

		switch a.FromPolicy {
		case "", "reject", "rewrite", "passthrough":
		default:
			add("%s (%s): from_policy must be reject, rewrite or passthrough", where, a.Username)
		}
		for _, pattern := range a.AllowedSenders {
			if err := policy.ValidatePattern(pattern); err != nil {
				add("%s (%s): %v", where, a.Username, err)
			}
		}
		for _, mailbox := range a.Mailboxes {
			if !mailboxAddresses[strings.ToLower(mailbox)] {
				// The mailbox may already exist in the database rather than in
				// this file; that is resolved at apply time. But a typo in a
				// self-contained file is worth catching here.
				continue
			}
		}
		if a.DefaultMailbox != "" && len(a.Mailboxes) > 0 {
			found := false
			for _, mailbox := range a.Mailboxes {
				if strings.EqualFold(mailbox, a.DefaultMailbox) {
					found = true
				}
			}
			if !found {
				add("%s (%s): default_mailbox %q is not in this account's mailboxes list", where, a.Username, a.DefaultMailbox)
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%d problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// Applier writes a bootstrap file into the store.
type Applier struct {
	DB      *store.DB
	Keyring *appcrypto.Keyring
	// Reconcile marks objects bootstrap-managed and updates existing ones;
	// otherwise existing objects are left exactly as they are.
	Reconcile bool
	Log       *slog.Logger
}

// Result summarizes what an apply did.
type Result struct {
	Created int
	Updated int
	Skipped int
}

// Apply writes the file's objects.
//
// Order matters: credentials, then mailboxes that reference them, then
// accounts that reference mailboxes.
func (a *Applier) Apply(ctx context.Context, f *File) (Result, error) {
	if a.Log == nil {
		a.Log = slog.Default()
	}
	var result Result

	credentialIDs := map[string]string{}
	for i := range f.Credentials {
		if err := a.applyCredential(ctx, &f.Credentials[i], credentialIDs, &result); err != nil {
			return result, err
		}
	}

	mailboxIDs := map[string]string{}
	for i := range f.Mailboxes {
		if err := a.applyMailbox(ctx, &f.Mailboxes[i], credentialIDs, mailboxIDs, &result); err != nil {
			return result, err
		}
	}

	for i := range f.Accounts {
		if err := a.applyAccount(ctx, &f.Accounts[i], mailboxIDs, &result); err != nil {
			return result, err
		}
	}

	a.Log.Info("bootstrap applied",
		"created", result.Created, "updated", result.Updated, "skipped", result.Skipped,
		"reconcile", a.Reconcile)
	return result, nil
}

func (a *Applier) managedBy() store.ManagedBy {
	if a.Reconcile {
		return store.ManagedByBootstrap
	}
	return store.ManagedByUI
}

func (a *Applier) applyCredential(ctx context.Context, c *Credential, ids map[string]string, result *Result) error {
	existing, err := a.DB.Credentials().GetByName(ctx, c.Name)
	switch {
	case err == nil:
		ids[c.Name] = existing.ID
		if !a.Reconcile {
			result.Skipped++
			return nil
		}
		return a.updateCredential(ctx, existing, c, result)
	case !errors.Is(err, store.ErrNotFound):
		return err
	}

	stored := &store.OAuthCredential{
		ID:            store.NewID(),
		Name:          c.Name,
		TenantID:      c.TenantID,
		ClientID:      c.ClientID,
		AuthType:      credentialAuthType(c),
		AuthorityHost: c.AuthorityHost,
		ManagedBy:     a.managedBy(),
	}
	if err := a.sealInto(stored, c); err != nil {
		return err
	}
	if err := a.DB.Credentials().Create(ctx, stored); err != nil {
		return fmt.Errorf("bootstrap: creating credential %q: %w", c.Name, err)
	}
	ids[c.Name] = stored.ID
	result.Created++
	a.audit(ctx, "credential.create", "credential", stored.ID, c.Name)
	return nil
}

func (a *Applier) updateCredential(ctx context.Context, stored *store.OAuthCredential, c *Credential, result *Result) error {
	stored.TenantID = c.TenantID
	stored.ClientID = c.ClientID
	stored.AuthType = credentialAuthType(c)
	stored.AuthorityHost = c.AuthorityHost
	stored.ManagedBy = store.ManagedByBootstrap
	if err := a.sealInto(stored, c); err != nil {
		return err
	}
	if err := a.DB.Credentials().Update(ctx, stored); err != nil {
		return fmt.Errorf("bootstrap: updating credential %q: %w", c.Name, err)
	}
	result.Updated++
	a.audit(ctx, "credential.update", "credential", stored.ID, c.Name)
	return nil
}

func credentialAuthType(c *Credential) store.AuthType {
	if c.AuthType == "certificate" {
		return store.AuthTypeCertificate
	}
	return store.AuthTypeSecret
}

func (a *Applier) sealInto(stored *store.OAuthCredential, c *Credential) error {
	if a.Keyring == nil {
		return errors.New("bootstrap: no encryption keys are configured, so secrets cannot be stored")
	}
	if c.ClientSecret != "" {
		sealed, err := a.Keyring.EncryptString(c.ClientSecret, stored.SecretContext())
		if err != nil {
			return fmt.Errorf("bootstrap: sealing the secret for %q: %w", c.Name, err)
		}
		stored.ClientSecretEnc = sealed
	}
	if c.CertificatePEM != "" {
		stored.CertificatePEM = c.CertificatePEM
	}
	if c.CertificateKeyPEM != "" {
		sealed, err := a.Keyring.EncryptString(c.CertificateKeyPEM, stored.CertificateKeyContext())
		if err != nil {
			return fmt.Errorf("bootstrap: sealing the certificate key for %q: %w", c.Name, err)
		}
		stored.CertificateKeyEnc = sealed
	}
	return nil
}

func (a *Applier) applyMailbox(ctx context.Context, m *Mailbox, credentialIDs, mailboxIDs map[string]string, result *Result) error {
	address := strings.ToLower(m.Address)

	credentialID, ok := credentialIDs[m.Credential]
	if !ok {
		// The credential may predate this file.
		existing, err := a.DB.Credentials().GetByName(ctx, m.Credential)
		if err != nil {
			return fmt.Errorf("bootstrap: mailbox %q references the credential %q, which is neither in this file nor in the database",
				m.Address, m.Credential)
		}
		credentialID = existing.ID
		credentialIDs[m.Credential] = credentialID
	}

	existing, lookupErr := a.DB.Mailboxes().GetByAddress(ctx, address)
	switch {
	case lookupErr == nil:
		mailboxIDs[address] = existing.ID
		if !a.Reconcile {
			result.Skipped++
			return nil
		}
		existing.DisplayName = m.DisplayName
		existing.OAuthCredentialID = credentialID
		existing.Transport = mailboxTransport(m)
		existing.RateLimitPerMin = store.NullInt(m.RateLimitPerMin)
		existing.MaxConcurrent = store.NullInt(m.MaxConcurrent)
		existing.Enabled = !m.Disabled
		existing.ManagedBy = store.ManagedByBootstrap
		if err := a.DB.Mailboxes().Update(ctx, existing); err != nil {
			return fmt.Errorf("bootstrap: updating mailbox %q: %w", m.Address, err)
		}
		result.Updated++
		a.audit(ctx, "mailbox.update", "mailbox", existing.ID, address)
		return nil
	case !errors.Is(lookupErr, store.ErrNotFound):
		return lookupErr
	}

	stored := &store.Mailbox{
		ID:                store.NewID(),
		Address:           address,
		DisplayName:       m.DisplayName,
		OAuthCredentialID: credentialID,
		Transport:         mailboxTransport(m),
		RateLimitPerMin:   store.NullInt(m.RateLimitPerMin),
		MaxConcurrent:     store.NullInt(m.MaxConcurrent),
		Enabled:           !m.Disabled,
		ManagedBy:         a.managedBy(),
	}
	if err := a.DB.Mailboxes().Create(ctx, stored); err != nil {
		return fmt.Errorf("bootstrap: creating mailbox %q: %w", m.Address, err)
	}
	mailboxIDs[address] = stored.ID
	result.Created++
	a.audit(ctx, "mailbox.create", "mailbox", stored.ID, address)
	return nil
}

func mailboxTransport(m *Mailbox) store.Transport {
	if m.Transport == "graph" {
		return store.TransportGraph
	}
	return store.TransportSMTP
}

func (a *Applier) applyAccount(ctx context.Context, acc *Account, mailboxIDs map[string]string, result *Result) error {
	// Resolve the mailbox addresses to identifiers, looking up any that predate
	// this file.
	var ids []string
	for _, address := range acc.Mailboxes {
		normalized := strings.ToLower(address)
		id, ok := mailboxIDs[normalized]
		if !ok {
			existing, err := a.DB.Mailboxes().GetByAddress(ctx, normalized)
			if err != nil {
				return fmt.Errorf("bootstrap: account %q references the mailbox %q, which is neither in this file nor in the database",
					acc.Username, address)
			}
			id = existing.ID
			mailboxIDs[normalized] = id
		}
		ids = append(ids, id)
	}

	defaultID := ""
	if acc.DefaultMailbox != "" {
		defaultID = mailboxIDs[strings.ToLower(acc.DefaultMailbox)]
	} else if len(ids) > 0 {
		defaultID = ids[0]
	}

	existing, lookupErr := a.DB.Accounts().GetByUsername(ctx, acc.Username)
	switch {
	case lookupErr == nil:
		if !a.Reconcile {
			result.Skipped++
			return nil
		}
		existing.Description = acc.Description
		existing.PasswordHash = acc.PasswordHash
		existing.DefaultMailboxID = store.NullString(defaultID)
		existing.FromPolicy = accountPolicy(acc)
		existing.AllowCIDRs = acc.AllowCIDRs
		existing.RateLimitPerMin = store.NullInt(acc.RateLimitPerMin)
		existing.Enabled = !acc.Disabled
		existing.ManagedBy = store.ManagedByBootstrap
		if err := a.DB.Accounts().Update(ctx, existing); err != nil {
			return fmt.Errorf("bootstrap: updating account %q: %w", acc.Username, err)
		}
		if err := a.linkAccount(ctx, existing.ID, ids, acc.AllowedSenders); err != nil {
			return err
		}
		result.Updated++
		a.audit(ctx, "account.update", "smtp_account", existing.ID, acc.Username)
		return nil
	case !errors.Is(lookupErr, store.ErrNotFound):
		return lookupErr
	}

	stored := &store.SMTPAccount{
		ID:               store.NewID(),
		Username:         acc.Username,
		PasswordHash:     acc.PasswordHash,
		Description:      acc.Description,
		DefaultMailboxID: store.NullString(defaultID),
		FromPolicy:       accountPolicy(acc),
		AllowCIDRs:       acc.AllowCIDRs,
		RateLimitPerMin:  store.NullInt(acc.RateLimitPerMin),
		Enabled:          !acc.Disabled,
		ManagedBy:        a.managedBy(),
	}
	if err := a.DB.Accounts().Create(ctx, stored); err != nil {
		return fmt.Errorf("bootstrap: creating account %q: %w", acc.Username, err)
	}
	if err := a.linkAccount(ctx, stored.ID, ids, acc.AllowedSenders); err != nil {
		return err
	}
	result.Created++
	a.audit(ctx, "account.create", "smtp_account", stored.ID, acc.Username)
	return nil
}

func accountPolicy(acc *Account) store.FromPolicy {
	switch acc.FromPolicy {
	case "rewrite":
		return store.FromPolicyRewrite
	case "passthrough":
		return store.FromPolicyPassthrough
	default:
		return store.FromPolicyReject
	}
}

func (a *Applier) linkAccount(ctx context.Context, accountID string, mailboxIDs, allowedSenders []string) error {
	if err := a.DB.Accounts().SetMailboxes(ctx, accountID, mailboxIDs); err != nil {
		return fmt.Errorf("bootstrap: linking mailboxes: %w", err)
	}
	if err := a.DB.Accounts().SetAllowedSenders(ctx, accountID, allowedSenders); err != nil {
		return fmt.Errorf("bootstrap: setting allowed senders: %w", err)
	}
	return nil
}

// audit records what bootstrap changed. Failures are logged, not fatal: the
// change itself succeeded.
func (a *Applier) audit(ctx context.Context, action, targetType, targetID, targetName string) {
	err := a.DB.Audit().Append(ctx, &store.AuditEntry{
		ActorType:  store.ActorBootstrap,
		ActorName:  "bootstrap",
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		TargetName: targetName,
	})
	if err != nil {
		a.Log.Warn("could not record a bootstrap change in the audit log",
			"action", action, "target", targetName, "reason", err)
	}
}
