package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditEntry records something that changed, and who changed it.
type AuditEntry struct {
	ID        string
	At        time.Time
	ActorType string
	ActorID   string
	ActorName string
	Action    string

	TargetType string
	TargetID   string
	TargetName string

	// Details is JSON describing the change. Secret values are replaced before
	// it is written; see MaskSecrets.
	Details string
	Result  string

	IP        string
	UserAgent string
}

// Actor types.
const (
	// ActorUser is a signed-in administrator.
	ActorUser = "user"
	// ActorSystem is the proxy acting on its own, e.g. a purge.
	ActorSystem = "system"
	// ActorBootstrap is the declarative bootstrap file.
	ActorBootstrap = "bootstrap"
)

// Audit results.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// AuditRepo appends and reads the audit log.
type AuditRepo struct{ db *DB }

// Audit returns the audit repository.
func (db *DB) Audit() *AuditRepo { return &AuditRepo{db: db} }

const auditColumns = `
	id, at, actor_type, actor_id, actor_name, action,
	target_type, target_id, target_name, details, result, ip, user_agent`

// Append writes one entry.
//
// The audit log is append-only: there is deliberately no update or delete, so
// the record of who changed what cannot be quietly edited from inside the
// application that produced it.
func (r *AuditRepo) Append(ctx context.Context, e *AuditEntry) error {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.Result == "" {
		e.Result = ResultSuccess
	}
	if e.Details == "" {
		e.Details = "{}"
	}

	_, err := r.db.ExecContext(ctx, r.db.Rebind(`
		INSERT INTO audit_logs (`+auditColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.ID, utc(e.At), e.ActorType, e.ActorID, e.ActorName, e.Action,
		e.TargetType, e.TargetID, e.TargetName, e.Details, e.Result, e.IP, e.UserAgent)
	if err != nil {
		return fmt.Errorf("store: appending an audit entry: %w", err)
	}
	return nil
}

// AuditFilter narrows an audit listing.
type AuditFilter struct {
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Since      time.Time
	Until      time.Time
	Limit      int
	Offset     int
}

// List returns audit entries, newest first.
func (r *AuditRepo) List(ctx context.Context, f AuditFilter) ([]*AuditEntry, error) {
	where, args := f.build()

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args = append(args, limit, f.Offset)

	rows, err := r.db.QueryContext(ctx, r.db.Rebind(
		`SELECT `+auditColumns+` FROM audit_logs`+where+
			` ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`), args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing audit entries: %w", err)
	}
	defer rows.Close()

	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		err := rows.Scan(&e.ID, &e.At, &e.ActorType, &e.ActorID, &e.ActorName, &e.Action,
			&e.TargetType, &e.TargetID, &e.TargetName, &e.Details, &e.Result, &e.IP, &e.UserAgent)
		if err != nil {
			return nil, fmt.Errorf("store: scanning an audit entry: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// Count returns how many entries match a filter.
func (r *AuditRepo) Count(ctx context.Context, f AuditFilter) (int64, error) {
	where, args := f.build()

	var n int64
	if err := r.db.QueryRowContext(ctx,
		r.db.Rebind(`SELECT COUNT(*) FROM audit_logs`+where), args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting audit entries: %w", err)
	}
	return n, nil
}

func (f AuditFilter) build() (where string, args []any) {
	var clauses []string

	if f.ActorID != "" {
		clauses = append(clauses, "actor_id = ?")
		args = append(args, f.ActorID)
	}
	if f.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, f.Action)
	}
	if f.TargetType != "" {
		clauses = append(clauses, "target_type = ?")
		args = append(args, f.TargetType)
	}
	if f.TargetID != "" {
		clauses = append(clauses, "target_id = ?")
		args = append(args, f.TargetID)
	}
	if !f.Since.IsZero() {
		clauses = append(clauses, "at >= ?")
		args = append(args, utc(f.Since))
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "at <= ?")
		args = append(args, utc(f.Until))
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// secretFields are never written to the audit log in the clear. The audit log
// is a record of *what changed*, not of the values involved; a rotated client
// secret sitting in an append-only table would outlive the rotation.
var secretFields = []string{
	"password", "passwordhash", "password_hash",
	"secret", "clientsecret", "client_secret", "client_secret_enc",
	"certificatekey", "certificate_key", "certificate_key_enc",
	"totp", "totpsecret", "totp_secret", "totp_secret_enc",
	"token", "accesstoken", "access_token", "refreshtoken", "refresh_token",
	"apikey", "api_key",
}

// MaskSecrets replaces the value of any secret-looking field with a placeholder
// and returns the JSON to store.
func MaskSecrets(details map[string]any) string {
	masked := maskMap(details)

	b, err := json.Marshal(masked)
	if err != nil {
		// Losing the detail is acceptable; losing the entry is not.
		return `{"error":"details could not be encoded"}`
	}
	return string(b)
}

func maskMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if isSecretField(k) {
			out[k] = redactedValue(v)
			continue
		}
		switch nested := v.(type) {
		case map[string]any:
			out[k] = maskMap(nested)
		case []any:
			out[k] = maskSlice(nested)
		default:
			out[k] = v
		}
	}
	return out
}

func maskSlice(in []any) []any {
	out := make([]any, len(in))
	for i, v := range in {
		switch nested := v.(type) {
		case map[string]any:
			out[i] = maskMap(nested)
		case []any:
			out[i] = maskSlice(nested)
		default:
			out[i] = v
		}
	}
	return out
}

// redactedValue keeps whether a value was set, which is the part that matters
// for an audit trail, without keeping the value.
func redactedValue(v any) string {
	if v == nil {
		return "(unset)"
	}
	if s, ok := v.(string); ok && s == "" {
		return "(unset)"
	}
	return "(redacted)"
}

func isSecretField(name string) bool {
	lowered := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
	for _, f := range secretFields {
		if lowered == f || strings.HasSuffix(lowered, "_"+f) {
			return true
		}
	}
	// Catch compound names such as "newPassword" or "oldClientSecret".
	for _, f := range []string{"password", "secret", "token", "apikey", "api_key"} {
		if strings.Contains(lowered, f) {
			return true
		}
	}
	return false
}
