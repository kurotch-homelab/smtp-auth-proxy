package bootstrap_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/bootstrap"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/testsupport/discardlog"
)

// A realistic file: one credential with its secret in the environment, one
// mailbox, one account whose hash came from `smtp-auth-proxy passwd`.
const sampleFile = `
credentials:
  - name: primary
    tenant_id: 11111111-1111-1111-1111-111111111111
    client_id: 22222222-2222-2222-2222-222222222222
    auth_type: secret
    client_secret: ${BOOTSTRAP_TEST_SECRET}

mailboxes:
  - address: Scanner@Example.com
    display_name: Scanner
    credential: primary
    rate_limit_per_min: 20

accounts:
  - username: svc-scanner
    description: the office scanner
    password_hash: $argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGg
    mailboxes: [scanner@example.com]
    from_policy: rewrite
    allow_cidrs: [10.0.0.0/8]
`

func writeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	return path
}

func keyring(t *testing.T) *appcrypto.Keyring {
	t.Helper()

	spec, err := appcrypto.GenerateKey("k1")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := appcrypto.NewKeyring(spec)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

func TestLoadExpandsAndValidates(t *testing.T) {
	t.Setenv("BOOTSTRAP_TEST_SECRET", "the-secret-value")

	f, err := bootstrap.Load(writeFile(t, sampleFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The secret came from the environment, not the file.
	if f.Credentials[0].ClientSecret != "the-secret-value" {
		t.Errorf("ClientSecret = %q, want the expanded value", f.Credentials[0].ClientSecret)
	}
}

func TestLoadRejections(t *testing.T) {
	t.Setenv("BOOTSTRAP_TEST_SECRET", "s")

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "unknown keys fail loudly",
			doc:  "credentials:\n  - name: x\n    tenant: oops\n",
			want: "tenant",
		},
		{
			// The single most dangerous mistake this file invites.
			name: "a plaintext password where the hash belongs",
			doc:  "accounts:\n  - username: svc\n    password_hash: hunter2-in-plaintext\n",
			want: "never the password itself",
		},
		{
			name: "duplicate mailbox addresses",
			doc: "credentials:\n  - name: c\n    tenant_id: t\n    client_id: i\n    client_secret: s\n" +
				"mailboxes:\n  - {address: a@example.com, credential: c}\n  - {address: A@Example.com, credential: c}\n",
			want: "declared twice",
		},
		{
			name: "a rate above the Exchange limit",
			doc: "credentials:\n  - name: c\n    tenant_id: t\n    client_id: i\n    client_secret: s\n" +
				"mailboxes:\n  - {address: a@example.com, credential: c, rate_limit_per_min: 100}\n",
			want: "30/minute",
		},
		{
			name: "a default mailbox outside the account's list",
			doc: "accounts:\n  - username: svc\n" +
				"    password_hash: $argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA\n" +
				"    mailboxes: [a@example.com]\n    default_mailbox: b@example.com\n",
			want: "not in this account's mailboxes",
		},
		{
			name: "a wildcard sender pattern",
			doc: "accounts:\n  - username: svc\n" +
				"    password_hash: $argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA\n" +
				"    allowed_senders: ['*']\n",
			want: "any address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := bootstrap.Load(writeFile(t, tt.doc))
			if err == nil {
				t.Fatal("Load accepted the document")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestApplyCreatesEverything(t *testing.T) {
	t.Setenv("BOOTSTRAP_TEST_SECRET", "the-secret-value")

	db := storetest.Open(t, store.DriverSQLite)
	kr := keyring(t)
	f, err := bootstrap.Load(writeFile(t, sampleFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	applier := &bootstrap.Applier{DB: db, Keyring: kr, Log: discardlog.Logger()}
	result, err := applier.Apply(t.Context(), f)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.Created != 3 {
		t.Errorf("Created = %d, want 3", result.Created)
	}

	// The credential's secret is sealed, and decrypts to what the environment held.
	credential, err := db.Credentials().GetByName(t.Context(), "primary")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	secret, err := kr.DecryptString(credential.ClientSecretEnc, credential.SecretContext())
	if err != nil || secret != "the-secret-value" {
		t.Errorf("the sealed secret round-trips to (%q, %v)", secret, err)
	}

	// The mailbox address is normalized and linked to the credential.
	mailbox, err := db.Mailboxes().GetByAddress(t.Context(), "scanner@example.com")
	if err != nil {
		t.Fatalf("GetByAddress: %v", err)
	}
	if mailbox.OAuthCredentialID != credential.ID {
		t.Error("the mailbox is not linked to its credential")
	}
	if !mailbox.RateLimitPerMin.Valid || mailbox.RateLimitPerMin.Int64 != 20 {
		t.Errorf("RateLimitPerMin = %+v, want 20", mailbox.RateLimitPerMin)
	}

	// The account carries the hash verbatim and is linked to the mailbox.
	account, err := db.Accounts().GetByUsername(t.Context(), "svc-scanner")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if account.FromPolicy != store.FromPolicyRewrite {
		t.Errorf("FromPolicy = %q", account.FromPolicy)
	}
	linked, err := db.Mailboxes().ListForAccount(t.Context(), account.ID)
	if err != nil || len(linked) != 1 {
		t.Errorf("ListForAccount = (%d, %v), want the one mailbox", len(linked), err)
	}

	// apply-once marks nothing as bootstrap-managed: the UI stays in charge.
	if credential.ManagedBy != store.ManagedByUI {
		t.Errorf("ManagedBy = %q, want ui in apply-once mode", credential.ManagedBy)
	}
}

func TestApplyOnceLeavesExistingObjectsAlone(t *testing.T) {
	t.Setenv("BOOTSTRAP_TEST_SECRET", "the-secret-value")

	db := storetest.Open(t, store.DriverSQLite)
	kr := keyring(t)
	f, err := bootstrap.Load(writeFile(t, sampleFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	applier := &bootstrap.Applier{DB: db, Keyring: kr, Log: discardlog.Logger()}
	if _, err := applier.Apply(t.Context(), f); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// The operator edits the mailbox in the UI.
	mailbox, err := db.Mailboxes().GetByAddress(t.Context(), "scanner@example.com")
	if err != nil {
		t.Fatalf("GetByAddress: %v", err)
	}
	mailbox.DisplayName = "Renamed by hand"
	if err := db.Mailboxes().Update(t.Context(), mailbox); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// A restart re-applies the file; apply-once must not undo the edit.
	result, err := applier.Apply(t.Context(), f)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if result.Created != 0 || result.Updated != 0 {
		t.Errorf("second apply-once = %+v, want everything skipped", result)
	}

	after, err := db.Mailboxes().GetByAddress(t.Context(), "scanner@example.com")
	if err != nil {
		t.Fatalf("GetByAddress: %v", err)
	}
	if after.DisplayName != "Renamed by hand" {
		t.Error("apply-once overwrote an operator's edit")
	}
}

func TestReconcileEnforcesTheFile(t *testing.T) {
	t.Setenv("BOOTSTRAP_TEST_SECRET", "the-secret-value")

	db := storetest.Open(t, store.DriverSQLite)
	kr := keyring(t)
	f, err := bootstrap.Load(writeFile(t, sampleFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	applier := &bootstrap.Applier{DB: db, Keyring: kr, Reconcile: true, Log: discardlog.Logger()}
	if _, err := applier.Apply(t.Context(), f); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Someone edits the database behind the file's back.
	mailbox, err := db.Mailboxes().GetByAddress(t.Context(), "scanner@example.com")
	if err != nil {
		t.Fatalf("GetByAddress: %v", err)
	}
	mailbox.DisplayName = "Drifted"
	if err := db.Mailboxes().Update(t.Context(), mailbox); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Reconcile puts it back, and the object is marked as the file's.
	result, err := applier.Apply(t.Context(), f)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if result.Updated == 0 {
		t.Errorf("reconcile = %+v, want updates", result)
	}

	after, err := db.Mailboxes().GetByAddress(t.Context(), "scanner@example.com")
	if err != nil {
		t.Fatalf("GetByAddress: %v", err)
	}
	if after.DisplayName != "Scanner" {
		t.Errorf("DisplayName = %q, want the file's value restored", after.DisplayName)
	}
	if after.ManagedBy != store.ManagedByBootstrap {
		t.Errorf("ManagedBy = %q, want bootstrap, which makes it read-only in the UI", after.ManagedBy)
	}
}

func TestApplyResolvesReferencesToExistingObjects(t *testing.T) {
	db := storetest.Open(t, store.DriverSQLite)
	kr := keyring(t)

	// A credential that predates the file.
	existing := &store.OAuthCredential{
		Name: "pre-existing", TenantID: "t", ClientID: "c", AuthType: store.AuthTypeSecret,
	}
	if err := db.Credentials().Create(t.Context(), existing); err != nil {
		t.Fatalf("Create: %v", err)
	}

	doc := `
mailboxes:
  - address: alerts@example.com
    credential: pre-existing
`
	f, err := bootstrap.Load(writeFile(t, doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	applier := &bootstrap.Applier{DB: db, Keyring: kr, Log: discardlog.Logger()}
	if _, err := applier.Apply(t.Context(), f); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	mailbox, err := db.Mailboxes().GetByAddress(t.Context(), "alerts@example.com")
	if err != nil {
		t.Fatalf("GetByAddress: %v", err)
	}
	if mailbox.OAuthCredentialID != existing.ID {
		t.Error("the mailbox is not linked to the pre-existing credential")
	}
}

func TestApplyFailsClearlyOnAMissingReference(t *testing.T) {
	db := storetest.Open(t, store.DriverSQLite)

	doc := `
mailboxes:
  - address: alerts@example.com
    credential: nowhere
`
	f, err := bootstrap.Load(writeFile(t, doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	applier := &bootstrap.Applier{DB: db, Keyring: keyring(t), Log: discardlog.Logger()}
	_, err = applier.Apply(t.Context(), f)
	if err == nil {
		t.Fatal("Apply succeeded with a dangling reference")
	}
	if !strings.Contains(err.Error(), "nowhere") {
		t.Errorf("the error does not name the missing credential: %v", err)
	}
}

func TestApplyRecordsItsChangesInTheAuditLog(t *testing.T) {
	t.Setenv("BOOTSTRAP_TEST_SECRET", "s")

	db := storetest.Open(t, store.DriverSQLite)
	f, err := bootstrap.Load(writeFile(t, sampleFile))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	applier := &bootstrap.Applier{DB: db, Keyring: keyring(t), Log: discardlog.Logger()}
	if _, err := applier.Apply(t.Context(), f); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	entries, err := db.Audit().List(t.Context(), store.AuditFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("the audit log has %d entries, want one per created object", len(entries))
	}
	for _, e := range entries {
		if e.ActorType != store.ActorBootstrap {
			t.Errorf("actor = %q, want bootstrap", e.ActorType)
		}
	}
}
