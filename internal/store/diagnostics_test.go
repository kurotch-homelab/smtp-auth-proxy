package store_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func TestDiagnosticRequestIsPersistentAndAtomic(t *testing.T) {
	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			db := storetest.Open(t, driver)
			mb := newMailbox(t, db, "shared@example.com")
			c, err := db.Credentials().Get(t.Context(), mb.OAuthCredentialID)
			if err != nil {
				t.Fatal(err)
			}
			c.ClientSecretEnc = "test-sealed-value"
			if err := db.Credentials().Update(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			requestID := store.NewID()
			var wg sync.WaitGroup
			ids := make(chan string, 8)
			for range 8 {
				wg.Go(func() {
					m := &store.Message{MailboxAddress: mb.Address, EnvelopeFrom: mb.Address, Recipients: []string{"to@example.net"}}
					id, _, err := db.Messages().EnqueueDiagnostic(t.Context(), "actor", requestID, mb.ID, "to@example.net", m, []byte("test body"))
					if err != nil {
						t.Error(err)
						return
					}
					ids <- id
				})
			}
			wg.Wait()
			close(ids)
			var id string
			for got := range ids {
				if id != "" && got != id {
					t.Error("duplicate messages")
				}
				id = got
			}
			if id == "" {
				t.Fatal("no message created")
			}
			got, err := db.Messages().Get(t.Context(), id)
			if err != nil {
				t.Fatal(err)
			}
			if got.Origin != "diagnostic" || got.SMTPAccountID.Valid || got.AccountUsername != "" {
				t.Fatalf("wrong origin: %+v", got)
			}
			count, err := db.Messages().Count(t.Context(), store.MessageFilter{})
			if err != nil || count != 1 {
				t.Fatalf("count=%d, %v", count, err)
			}
			if err := db.Messages().Delete(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			_, _, err = db.Messages().EnqueueDiagnostic(t.Context(), "actor", requestID, mb.ID, "to@example.net", &store.Message{}, []byte("test"))
			if !errors.Is(err, store.ErrStateConflict) {
				t.Fatalf("deleted request resent: %v", err)
			}
		})
	}
}

func TestOperatorActionStateMatrix(t *testing.T) {
	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			db := storetest.Open(t, driver)
			for _, status := range []store.MessageStatus{store.StatusQueued, store.StatusSending, store.StatusDeferred, store.StatusFailed, store.StatusHeld, store.StatusSent} {
				for _, action := range []string{"retry", "hold", "delete"} {
					m := &store.Message{Status: status, EnvelopeFrom: "a@example.com", Recipients: []string{"b@example.com"}}
					if err := db.Messages().Enqueue(t.Context(), m, []byte("body")); err != nil {
						t.Fatal(err)
					}
					var err error
					allowed := false
					switch action {
					case "retry":
						err = db.Messages().Requeue(t.Context(), m.ID)
						allowed = status == store.StatusFailed || status == store.StatusDeferred || status == store.StatusHeld
					case "hold":
						err = db.Messages().Hold(t.Context(), m.ID)
						allowed = status == store.StatusQueued || status == store.StatusDeferred || status == store.StatusFailed
					case "delete":
						err = db.Messages().Delete(t.Context(), m.ID)
						allowed = status != store.StatusSending
					}
					if (allowed && err != nil) || (!allowed && !errors.Is(err, store.ErrStateConflict)) {
						t.Errorf("%s %s: %v", status, action, err)
					}
				}
			}
		})
	}
}
