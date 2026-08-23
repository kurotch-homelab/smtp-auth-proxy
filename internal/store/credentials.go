package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CredentialRepo reads and writes Microsoft Entra application registrations.
type CredentialRepo struct{ db *DB }

// Credentials returns the credential repository.
func (db *DB) Credentials() *CredentialRepo { return &CredentialRepo{db: db} }

// The name contains "secret" only because the column does; gosec's
// hardcoded-credential heuristic matches on that.
//
//nolint:gosec // G101: this is a SQL column list, not a credential
const credentialColumns = `
	id, name, tenant_id, client_id, auth_type,
	client_secret_enc, certificate_pem, certificate_key_enc, certificate_thumbprint,
	authority_host, expires_at, managed_by, created_at, updated_at`

func scanCredential(row interface{ Scan(...any) error }) (*OAuthCredential, error) {
	var c OAuthCredential
	err := row.Scan(
		&c.ID, &c.Name, &c.TenantID, &c.ClientID, &c.AuthType,
		&c.ClientSecretEnc, &c.CertificatePEM, &c.CertificateKeyEnc, &c.CertificateThumbprint,
		&c.AuthorityHost, &c.ExpiresAt, &c.ManagedBy, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Create inserts a credential, assigning its ID and timestamps.
func (r *CredentialRepo) Create(ctx context.Context, c *OAuthCredential) error {
	if c.ID == "" {
		c.ID = NewID()
	}
	now := time.Now().UTC()
	c.CreatedAt, c.UpdatedAt = now, now
	if c.ManagedBy == "" {
		c.ManagedBy = ManagedByUI
	}

	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO oauth_credentials (`+credentialColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		c.ID, c.Name, c.TenantID, c.ClientID, c.AuthType,
		c.ClientSecretEnc, c.CertificatePEM, c.CertificateKeyEnc, c.CertificateThumbprint,
		c.AuthorityHost, c.ExpiresAt, c.ManagedBy, c.CreatedAt, c.UpdatedAt)
	return translateError(r.db.Dialect(), err, "credential "+c.Name)
}

// Get returns one credential by ID.
func (r *CredentialRepo) Get(ctx context.Context, id string) (*OAuthCredential, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+credentialColumns+` FROM oauth_credentials WHERE id = ?`), id)
	c, err := scanCredential(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "credential "+id)
	}
	return c, nil
}

// GetByName returns one credential by its unique name.
func (r *CredentialRepo) GetByName(ctx context.Context, name string) (*OAuthCredential, error) {
	row := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT `+credentialColumns+` FROM oauth_credentials WHERE name = ?`), name)
	c, err := scanCredential(row)
	if err != nil {
		return nil, translateError(r.db.Dialect(), err, "credential "+name)
	}
	return c, nil
}

// List returns every credential, ordered by name.
func (r *CredentialRepo) List(ctx context.Context) ([]*OAuthCredential, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+credentialColumns+` FROM oauth_credentials ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing credentials: %w", err)
	}
	defer rows.Close()

	var out []*OAuthCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning credential: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Update writes every mutable field. Callers read, modify and write back, so a
// partial update cannot silently drop a field it forgot to mention.
func (r *CredentialRepo) Update(ctx context.Context, c *OAuthCredential) error {
	c.UpdatedAt = time.Now().UTC()

	res, err := r.db.ExecContext(ctx, r.db.Rebind(`
		UPDATE oauth_credentials SET
			name = ?, tenant_id = ?, client_id = ?, auth_type = ?,
			client_secret_enc = ?, certificate_pem = ?, certificate_key_enc = ?,
			certificate_thumbprint = ?, authority_host = ?, expires_at = ?,
			managed_by = ?, updated_at = ?
		WHERE id = ?`),
		c.Name, c.TenantID, c.ClientID, c.AuthType,
		c.ClientSecretEnc, c.CertificatePEM, c.CertificateKeyEnc,
		c.CertificateThumbprint, c.AuthorityHost, c.ExpiresAt,
		c.ManagedBy, c.UpdatedAt, c.ID)
	if err != nil {
		return translateError(r.db.Dialect(), err, "credential "+c.Name)
	}
	return requireOneRow(res, "credential "+c.ID)
}

// Delete removes a credential. It fails while a mailbox still uses it, rather
// than leaving mailboxes that can no longer authenticate.
func (r *CredentialRepo) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx,
		r.db.Rebind(`DELETE FROM oauth_credentials WHERE id = ?`), id)
	if err != nil {
		return translateError(r.db.Dialect(), err, "credential "+id)
	}
	return requireOneRow(res, "credential "+id)
}

// ExpiringBefore lists credentials whose secret or certificate expires before a
// cutoff, so the dashboard can warn ahead of an outage.
func (r *CredentialRepo) ExpiringBefore(ctx context.Context, cutoff time.Time) ([]*OAuthCredential, error) {
	rows, err := r.db.QueryContext(ctx, r.db.Rebind(
		`SELECT `+credentialColumns+` FROM oauth_credentials
		 WHERE expires_at IS NOT NULL AND expires_at < ?
		 ORDER BY expires_at`), cutoff)
	if err != nil {
		return nil, fmt.Errorf("store: listing expiring credentials: %w", err)
	}
	defer rows.Close()

	var out []*OAuthCredential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning credential: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// requireOneRow turns "no rows affected" into ErrNotFound, so an update or
// delete against a missing ID does not look like success.
func requireOneRow(res sql.Result, what string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: reading affected rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	}
	return nil
}
