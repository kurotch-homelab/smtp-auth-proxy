package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Repository errors.
var (
	// ErrNotFound is returned when a lookup matches no row.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a unique constraint would be violated, e.g.
	// two SMTP accounts with the same username.
	ErrConflict = errors.New("store: already exists")
	// ErrReferenced is returned when a row cannot be deleted because something
	// still points at it, e.g. a credential still used by a mailbox.
	ErrReferenced = errors.New("store: still referenced by another object")
	// ErrImmutable is returned when an object declared in a bootstrap file is
	// edited through the admin API while bootstrap runs in reconcile mode.
	ErrImmutable = errors.New("store: object is managed by the bootstrap file")
)

// ManagedBy records where an object came from.
type ManagedBy string

// Provenance values.
const (
	// ManagedByUI is anything an operator created through the admin interface.
	ManagedByUI ManagedBy = "ui"
	// ManagedByBootstrap is declared in a bootstrap file. In reconcile mode the
	// admin API refuses to modify these, so the file stays authoritative.
	ManagedByBootstrap ManagedBy = "bootstrap"
)

// AuthType selects how a credential proves itself to Microsoft Entra.
type AuthType string

// Credential authentication types.
const (
	// AuthTypeSecret is a client secret. Simple, but it expires and has to be
	// rotated by hand.
	AuthTypeSecret AuthType = "secret"
	// AuthTypeCertificate is private_key_jwt. Longer-lived and never transmitted.
	AuthTypeCertificate AuthType = "certificate"
)

// Transport selects how a mailbox's mail reaches Microsoft 365.
type Transport string

// Upstream transports.
const (
	// TransportSMTP relays through smtp.office365.com using SASL XOAUTH2.
	TransportSMTP Transport = "smtp"
	// TransportGraph posts the MIME message to the Graph sendMail endpoint.
	TransportGraph Transport = "graph"
)

// FromPolicy decides what happens when a message's From header is not an
// address the submitting account is allowed to send as.
type FromPolicy string

// Sender policies.
const (
	// FromPolicyReject refuses the message with 550. The default: a device
	// sending as the wrong identity is a configuration error worth surfacing.
	FromPolicyReject FromPolicy = "reject"
	// FromPolicyRewrite replaces From with the resolved mailbox and preserves
	// the original in Reply-To, for devices whose sender cannot be configured.
	FromPolicyRewrite FromPolicy = "rewrite"
	// FromPolicyPassthrough sends the header unchanged and lets Exchange decide.
	FromPolicyPassthrough FromPolicy = "passthrough"
)

// MessageStatus is where a queued message is in its lifecycle.
type MessageStatus string

// Message statuses.
const (
	// StatusQueued is accepted and waiting for a worker.
	StatusQueued MessageStatus = "queued"
	// StatusSending is leased by a worker and in flight.
	StatusSending MessageStatus = "sending"
	// StatusSent was accepted by Microsoft 365.
	StatusSent MessageStatus = "sent"
	// StatusDeferred failed temporarily and will be retried.
	StatusDeferred MessageStatus = "deferred"
	// StatusFailed will not be retried: permanently rejected, or out of attempts.
	StatusFailed MessageStatus = "failed"
	// StatusHeld was paused by an operator and is not eligible for delivery.
	StatusHeld MessageStatus = "held"
)

// Role is an admin user's permission level.
type Role string

// Admin roles, from most to least privileged.
const (
	// RoleAdmin manages every setting, including OAuth credentials and users.
	RoleAdmin Role = "admin"
	// RoleOperator works the queue and reads history, but changes no settings.
	RoleOperator Role = "operator"
	// RoleViewer reads only.
	RoleViewer Role = "viewer"
)

// OAuthCredential is a Microsoft Entra application registration the proxy
// authenticates as. One credential can serve many mailboxes: with the client
// credentials flow, the mailbox is selected by the XOAUTH2 "user=" field rather
// than by the token.
type OAuthCredential struct {
	ID       string
	Name     string
	TenantID string
	ClientID string
	AuthType AuthType

	// ClientSecretEnc, CertificateKeyEnc and CertificatePEM hold the credential
	// material. The two *Enc fields are sealed by the crypto keyring and are
	// never returned through the admin API.
	ClientSecretEnc       string
	CertificatePEM        string
	CertificateKeyEnc     string
	CertificateThumbprint string

	AuthorityHost string
	// ExpiresAt is when the secret or certificate stops working, so the UI can
	// warn before mail starts bouncing.
	ExpiresAt sql.NullTime

	ManagedBy ManagedBy
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretContext is the value bound into the credential's sealed secret. It ties
// the ciphertext to this row, so it cannot be moved to another one.
func (c *OAuthCredential) SecretContext() string {
	return "oauth_credentials/client_secret/" + c.ID
}

// CertificateKeyContext is SecretContext for the certificate private key.
func (c *OAuthCredential) CertificateKeyContext() string {
	return "oauth_credentials/certificate_key/" + c.ID
}

// Mailbox is a shared mailbox the proxy may send as.
type Mailbox struct {
	ID string
	// Address is the shared mailbox's SMTP address. It is the value placed in
	// the XOAUTH2 "user=" field, which is what lets one app registration send
	// as several different mailboxes.
	Address           string
	DisplayName       string
	OAuthCredentialID string
	Transport         Transport

	// RateLimitPerMin and MaxConcurrent override the global defaults. Exchange
	// Online allows 30 messages/minute and 3 concurrent connections per mailbox.
	RateLimitPerMin sql.NullInt64
	MaxConcurrent   sql.NullInt64

	Enabled   bool
	ManagedBy ManagedBy
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SMTPAccount is one LAN service's credentials.
type SMTPAccount struct {
	ID           string
	Username     string
	PasswordHash string
	Description  string

	// DefaultMailboxID is used when the From header matches none of the
	// mailboxes this account may send as.
	DefaultMailboxID sql.NullString
	FromPolicy       FromPolicy
	// AllowCIDRs restricts where this account may connect from. Empty means any.
	AllowCIDRs []string
	// RateLimitPerMin caps this account specifically, below the mailbox budget.
	RateLimitPerMin sql.NullInt64

	Enabled    bool
	LastUsedAt sql.NullTime
	ManagedBy  ManagedBy
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// AllowedSender is an address pattern an account may put in From beyond the
// addresses of its own mailboxes. A pattern is either an exact address or
// *@domain.
type AllowedSender struct {
	ID            string
	SMTPAccountID string
	Pattern       string
	CreatedAt     time.Time
}

// Message is one submission working its way to Microsoft 365.
type Message struct {
	ID            string
	SMTPAccountID sql.NullString
	MailboxID     sql.NullString
	// AccountUsername and MailboxAddress are denormalized so history stays
	// readable after the account or mailbox is deleted.
	AccountUsername string
	MailboxAddress  string

	EnvelopeFrom   string
	HeaderFrom     string
	Recipients     []string
	RecipientCount int
	SizeBytes      int64
	// Subject is only populated when log.include_subjects is enabled.
	Subject   string
	MessageID string

	Status        MessageStatus
	Attempts      int
	NextAttemptAt time.Time
	// LeaseOwner and LeaseExpiresAt let several replicas share one queue: a
	// worker owns a message only until the lease expires.
	LeaseOwner     sql.NullString
	LeaseExpiresAt sql.NullTime

	LastError          string
	LastErrorCode      string
	LastErrorPermanent bool

	ClientIP string
	// BlobRef points at the on-disk body when storage.blob is fs; otherwise the
	// body lives in message_blobs.
	BlobRef string

	ReceivedAt time.Time
	SentAt     sql.NullTime
	UpdatedAt  time.Time
}

// NullString wraps a string, treating empty as NULL.
func NullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// NullTime wraps a time, treating the zero value as NULL.
func NullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t.UTC(), Valid: !t.IsZero()}
}

// utc normalizes a timestamp before it is written.
//
// SQLite stores a time.Time as text including its offset, so a value in local
// time compares wrong against one in UTC: an expired row looks live, and a due
// row looks scheduled. Every write path runs caller-supplied times through
// this rather than trusting them.
func utc(t time.Time) time.Time { return t.UTC() }

// utcNull is utc for a nullable timestamp.
func utcNull(t sql.NullTime) sql.NullTime {
	if !t.Valid {
		return t
	}
	t.Time = t.Time.UTC()
	return t
}

// NullInt wraps an int, treating zero as NULL. The per-object rate limits use
// this: "unset" there means "inherit the global default", which is different
// from a limit of zero.
func NullInt(n int) sql.NullInt64 {
	return sql.NullInt64{Int64: int64(n), Valid: n > 0}
}

// translateError maps a driver error onto the sentinel errors above, so callers
// can respond to a duplicate username without knowing which engine they are on.
func translateError(d Dialect, err error, what string) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	case d.IsUniqueViolation(err):
		return fmt.Errorf("%w: %s", ErrConflict, what)
	case d.IsForeignKeyViolation(err):
		return fmt.Errorf("%w: %s", ErrReferenced, what)
	default:
		return err
	}
}
