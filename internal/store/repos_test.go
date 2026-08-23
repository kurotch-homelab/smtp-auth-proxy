package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func TestCredentialCRUD(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			repo := db.Credentials()

			created := newCredential(t, db, "primary")
			if created.ID == "" {
				t.Fatal("Create did not assign an ID")
			}
			if created.ManagedBy != store.ManagedByUI {
				t.Errorf("ManagedBy = %q, want ui", created.ManagedBy)
			}

			got, err := repo.Get(t.Context(), created.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Name != "primary" || got.TenantID != created.TenantID {
				t.Errorf("Get returned %+v, want the created credential", got)
			}
			if got.ClientSecretEnc != created.ClientSecretEnc {
				t.Errorf("the sealed secret did not round-trip")
			}

			byName, err := repo.GetByName(t.Context(), "primary")
			if err != nil || byName.ID != created.ID {
				t.Errorf("GetByName = (%v, %v)", byName, err)
			}

			got.Name = "renamed"
			got.AuthType = store.AuthTypeCertificate
			got.CertificateThumbprint = "AABBCC"
			if err := repo.Update(t.Context(), got); err != nil {
				t.Fatalf("Update: %v", err)
			}
			reread, err := repo.Get(t.Context(), created.ID)
			if err != nil {
				t.Fatalf("Get after Update: %v", err)
			}
			if reread.Name != "renamed" || reread.AuthType != store.AuthTypeCertificate {
				t.Errorf("Update did not persist: %+v", reread)
			}
			if !reread.UpdatedAt.After(reread.CreatedAt) && !reread.UpdatedAt.Equal(reread.CreatedAt) {
				t.Errorf("UpdatedAt %v predates CreatedAt %v", reread.UpdatedAt, reread.CreatedAt)
			}

			if err := repo.Delete(t.Context(), created.ID); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := repo.Get(t.Context(), created.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("Get after Delete = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestCredentialErrors(t *testing.T) {
	// Not parallel: the subtests below build on each other's state.
	db := storetest.Open(t, store.DriverSQLite)
	repo := db.Credentials()
	c := newCredential(t, db, "primary")

	t.Run("duplicate name conflicts", func(t *testing.T) {
		dup := *c
		dup.ID = ""
		if err := repo.Create(t.Context(), &dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("Create with a duplicate name = %v, want ErrConflict", err)
		}
	})

	t.Run("missing id is not found", func(t *testing.T) {
		if _, err := repo.Get(t.Context(), "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get = %v, want ErrNotFound", err)
		}
		if err := repo.Delete(t.Context(), "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete = %v, want ErrNotFound", err)
		}
		missing := &store.OAuthCredential{ID: "nope", Name: "x", AuthType: store.AuthTypeSecret}
		if err := repo.Update(t.Context(), missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update = %v, want ErrNotFound", err)
		}
	})

	t.Run("credential in use cannot be deleted", func(t *testing.T) {
		// Deleting it would leave a mailbox that can no longer authenticate,
		// which surfaces as mail silently failing rather than a clear error.
		mb := &store.Mailbox{Address: "shared@example.com", OAuthCredentialID: c.ID, Transport: store.TransportSMTP}
		if err := db.Mailboxes().Create(t.Context(), mb); err != nil {
			t.Fatalf("creating mailbox: %v", err)
		}
		if err := repo.Delete(t.Context(), c.ID); !errors.Is(err, store.ErrReferenced) {
			t.Errorf("Delete of a credential in use = %v, want ErrReferenced", err)
		}
	})
}

func TestCredentialExpiringBefore(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	repo := db.Credentials()
	now := time.Now().UTC()

	soon := newCredential(t, db, "expires-soon")
	soon.ExpiresAt = store.NullTime(now.Add(24 * time.Hour))
	if err := repo.Update(t.Context(), soon); err != nil {
		t.Fatalf("Update: %v", err)
	}

	later := newCredential(t, db, "expires-later")
	later.ExpiresAt = store.NullTime(now.Add(90 * 24 * time.Hour))
	if err := repo.Update(t.Context(), later); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// A credential with no expiry must not be reported as expiring.
	newCredential(t, db, "no-expiry")

	got, err := repo.ExpiringBefore(t.Context(), now.Add(30*24*time.Hour))
	if err != nil {
		t.Fatalf("ExpiringBefore: %v", err)
	}
	if len(got) != 1 || got[0].Name != "expires-soon" {
		names := make([]string, len(got))
		for i, c := range got {
			names[i] = c.Name
		}
		t.Errorf("ExpiringBefore returned %v, want [expires-soon]", names)
	}
}

func TestMailboxCRUD(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			repo := db.Mailboxes()

			mb := newMailbox(t, db, "shared@example.com")
			if mb.Transport != store.TransportSMTP {
				t.Errorf("Transport = %q, want the smtp default", mb.Transport)
			}

			byAddress, err := repo.GetByAddress(t.Context(), "shared@example.com")
			if err != nil || byAddress.ID != mb.ID {
				t.Fatalf("GetByAddress = (%v, %v)", byAddress, err)
			}

			// An unset per-mailbox limit must stay NULL, meaning "inherit the
			// global default" rather than "no messages at all".
			if byAddress.RateLimitPerMin.Valid {
				t.Errorf("RateLimitPerMin = %v, want NULL when unset", byAddress.RateLimitPerMin)
			}

			mb.RateLimitPerMin = store.NullInt(20)
			mb.MaxConcurrent = store.NullInt(1)
			mb.Transport = store.TransportGraph
			mb.Enabled = false
			if err := repo.Update(t.Context(), mb); err != nil {
				t.Fatalf("Update: %v", err)
			}

			reread, err := repo.Get(t.Context(), mb.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !reread.RateLimitPerMin.Valid || reread.RateLimitPerMin.Int64 != 20 {
				t.Errorf("RateLimitPerMin = %+v, want 20", reread.RateLimitPerMin)
			}
			if reread.Transport != store.TransportGraph || reread.Enabled {
				t.Errorf("Update did not persist: %+v", reread)
			}

			list, err := repo.List(t.Context())
			if err != nil || len(list) != 1 {
				t.Fatalf("List = (%d mailboxes, %v), want 1", len(list), err)
			}
		})
	}
}

func TestMailboxListForAccount(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	sales := newMailbox(t, db, "sales@example.com")
	support := newMailbox(t, db, "support@example.com")
	unrelated := newMailbox(t, db, "hr@example.com")

	account := newAccount(t, db, "svc-printer")
	if err := db.Accounts().SetMailboxes(t.Context(), account.ID, []string{sales.ID, support.ID}); err != nil {
		t.Fatalf("SetMailboxes: %v", err)
	}

	got, err := db.Mailboxes().ListForAccount(t.Context(), account.ID)
	if err != nil {
		t.Fatalf("ListForAccount: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListForAccount returned %d mailboxes, want 2", len(got))
	}
	for _, m := range got {
		if m.ID == unrelated.ID {
			t.Error("ListForAccount returned a mailbox the account may not send as")
		}
	}
}

func TestMailboxListForAccountIncludesTheDefault(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")

	// A single-mailbox account should only need its default set; requiring the
	// join table as well would be a footgun.
	account := newAccount(t, db, "svc-nas")
	account.DefaultMailboxID = store.NullString(mb.ID)
	if err := db.Accounts().Update(t.Context(), account); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := db.Mailboxes().ListForAccount(t.Context(), account.ID)
	if err != nil {
		t.Fatalf("ListForAccount: %v", err)
	}
	if len(got) != 1 || got[0].ID != mb.ID {
		t.Errorf("ListForAccount returned %d mailboxes, want the default one", len(got))
	}
}

func TestAccountCRUD(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			repo := db.Accounts()

			a := newAccount(t, db, "svc-printer")
			if a.FromPolicy != store.FromPolicyReject {
				t.Errorf("FromPolicy = %q, want reject by default", a.FromPolicy)
			}

			byUsername, err := repo.GetByUsername(t.Context(), "svc-printer")
			if err != nil || byUsername.ID != a.ID {
				t.Fatalf("GetByUsername = (%v, %v)", byUsername, err)
			}

			a.AllowCIDRs = []string{"10.0.0.0/8", "192.168.1.0/24"}
			a.FromPolicy = store.FromPolicyRewrite
			a.Description = "the office MFP"
			if err := repo.Update(t.Context(), a); err != nil {
				t.Fatalf("Update: %v", err)
			}

			reread, err := repo.Get(t.Context(), a.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if len(reread.AllowCIDRs) != 2 || reread.AllowCIDRs[0] != "10.0.0.0/8" {
				t.Errorf("AllowCIDRs = %v, want the two CIDRs back", reread.AllowCIDRs)
			}
			if reread.FromPolicy != store.FromPolicyRewrite {
				t.Errorf("FromPolicy = %q, want rewrite", reread.FromPolicy)
			}

			if err := repo.Delete(t.Context(), a.ID); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := repo.GetByUsername(t.Context(), "svc-printer"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("GetByUsername after Delete = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestAccountEmptyCIDRListRoundTrips(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a := newAccount(t, db, "svc-any-source")

	got, err := db.Accounts().Get(t.Context(), a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Empty must mean "any source address", not a list containing "".
	if len(got.AllowCIDRs) != 0 {
		t.Errorf("AllowCIDRs = %#v, want empty", got.AllowCIDRs)
	}
}

func TestAccountTouchLastUsed(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a := newAccount(t, db, "svc-printer")

	at := time.Now().UTC().Truncate(time.Second)
	if err := db.Accounts().TouchLastUsed(t.Context(), a.ID, at); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}

	got, err := db.Accounts().Get(t.Context(), a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LastUsedAt.Valid {
		t.Fatal("LastUsedAt is still NULL")
	}
	if diff := got.LastUsedAt.Time.Sub(at).Abs(); diff > time.Second {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt.Time, at)
	}
}

func TestAccountMailboxLinksAreReplacedNotAppended(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a := newAccount(t, db, "svc-printer")
	first := newMailbox(t, db, "one@example.com")
	second := newMailbox(t, db, "two@example.com")

	if err := db.Accounts().SetMailboxes(t.Context(), a.ID, []string{first.ID}); err != nil {
		t.Fatalf("SetMailboxes: %v", err)
	}
	// Setting the list again must replace it; an operator removing a mailbox in
	// the UI expects the account to lose access to it.
	if err := db.Accounts().SetMailboxes(t.Context(), a.ID, []string{second.ID}); err != nil {
		t.Fatalf("SetMailboxes: %v", err)
	}

	got, err := db.Mailboxes().ListForAccount(t.Context(), a.ID)
	if err != nil {
		t.Fatalf("ListForAccount: %v", err)
	}
	if len(got) != 1 || got[0].ID != second.ID {
		t.Errorf("ListForAccount returned %d mailboxes, want only the second", len(got))
	}
}

func TestAccountMailboxLinksTolerateDuplicates(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a := newAccount(t, db, "svc-printer")
	mb := newMailbox(t, db, "one@example.com")

	// A UI that submits the same mailbox twice should not produce an error.
	if err := db.Accounts().SetMailboxes(t.Context(), a.ID, []string{mb.ID, mb.ID}); err != nil {
		t.Fatalf("SetMailboxes with a duplicate: %v", err)
	}
	got, err := db.Mailboxes().ListForAccount(t.Context(), a.ID)
	if err != nil || len(got) != 1 {
		t.Errorf("ListForAccount = (%d, %v), want 1 mailbox", len(got), err)
	}
}

func TestAllowedSenders(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	a := newAccount(t, db, "svc-printer")

	if err := db.Accounts().SetAllowedSenders(t.Context(), a.ID,
		[]string{"noreply@example.com", "*@example.org", "noreply@example.com"}); err != nil {
		t.Fatalf("SetAllowedSenders: %v", err)
	}

	got, err := db.Accounts().AllowedSenders(t.Context(), a.ID)
	if err != nil {
		t.Fatalf("AllowedSenders: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("AllowedSenders returned %d patterns, want 2 after deduplication", len(got))
	}

	// Deleting the account must take its patterns with it.
	if err := db.Accounts().Delete(t.Context(), a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	after, err := db.Accounts().AllowedSenders(t.Context(), a.ID)
	if err != nil {
		t.Fatalf("AllowedSenders after Delete: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("%d allowed senders survived the account", len(after))
	}
}
