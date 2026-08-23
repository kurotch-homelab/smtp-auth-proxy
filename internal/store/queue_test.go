package store_test

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
)

func TestEnqueueStoresMessageAndBody(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			mb := newMailbox(t, db, "shared@example.com")

			m := &store.Message{
				MailboxID:      store.NullString(mb.ID),
				MailboxAddress: mb.Address,
				EnvelopeFrom:   mb.Address,
				HeaderFrom:     mb.Address,
				Recipients:     []string{"a@example.net", "b@example.net"},
				SizeBytes:      21,
			}
			body := []byte("Subject: hello\r\n\r\nbody")
			if err := db.Messages().Enqueue(t.Context(), m, body); err != nil {
				t.Fatalf("Enqueue: %v", err)
			}

			if m.Status != store.StatusQueued {
				t.Errorf("Status = %q, want queued", m.Status)
			}
			if m.RecipientCount != 2 {
				t.Errorf("RecipientCount = %d, want 2", m.RecipientCount)
			}

			got, err := db.Messages().Get(t.Context(), m.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if len(got.Recipients) != 2 || got.Recipients[1] != "b@example.net" {
				t.Errorf("Recipients = %v, want both back in order", got.Recipients)
			}

			gotBody, err := db.Messages().Body(t.Context(), m.ID)
			if err != nil {
				t.Fatalf("Body: %v", err)
			}
			if !bytes.Equal(gotBody, body) {
				t.Errorf("Body = %q, want %q", gotBody, body)
			}
		})
	}
}

func TestEnqueueIsAtomic(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)

	// A mailbox that does not exist makes the message insert fail. The body
	// insert must not survive it, or the blob would be orphaned.
	m := &store.Message{
		MailboxID:    store.NullString("no-such-mailbox"),
		EnvelopeFrom: "a@example.com",
		Recipients:   []string{"b@example.net"},
	}
	if err := db.Messages().Enqueue(t.Context(), m, []byte("body")); err == nil {
		t.Fatal("Enqueue succeeded with a dangling mailbox reference")
	}

	var blobs int
	if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM message_blobs").Scan(&blobs); err != nil {
		t.Fatalf("counting blobs: %v", err)
	}
	if blobs != 0 {
		t.Errorf("%d orphaned message bodies were left behind", blobs)
	}
}

func TestClaimAndMarkSent(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			mb := newMailbox(t, db, "shared@example.com")
			m := enqueue(t, db, mb, "to@example.net")

			claimed, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 10, time.Minute)
			if err != nil {
				t.Fatalf("ClaimMessages: %v", err)
			}
			if len(claimed) != 1 || claimed[0].ID != m.ID {
				t.Fatalf("claimed %d messages, want the one that was queued", len(claimed))
			}
			if claimed[0].Status != store.StatusSending {
				t.Errorf("Status = %q, want sending", claimed[0].Status)
			}
			if !claimed[0].LeaseOwner.Valid || claimed[0].LeaseOwner.String != "worker-1" {
				t.Errorf("LeaseOwner = %+v, want worker-1", claimed[0].LeaseOwner)
			}

			// A second worker must find nothing while the lease is live.
			other, err := db.Messages().ClaimMessages(t.Context(), "worker-2", 10, time.Minute)
			if err != nil {
				t.Fatalf("second ClaimMessages: %v", err)
			}
			if len(other) != 0 {
				t.Errorf("a second worker claimed %d leased messages", len(other))
			}

			if err := db.Messages().MarkSent(t.Context(), m.ID, "worker-1"); err != nil {
				t.Fatalf("MarkSent: %v", err)
			}
			got, err := db.Messages().Get(t.Context(), m.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Status != store.StatusSent {
				t.Errorf("Status = %q, want sent", got.Status)
			}
			if got.Attempts != 1 {
				t.Errorf("Attempts = %d, want 1", got.Attempts)
			}
			if !got.SentAt.Valid {
				t.Error("SentAt is still NULL")
			}
			if got.LeaseOwner.Valid {
				t.Error("the lease was not released")
			}
		})
	}
}

// Two workers racing for the same messages must never both get one: that is a
// duplicate delivery, and the recipient sees the mail twice.
func TestConcurrentClaimsNeverOverlap(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			mb := newMailbox(t, db, "shared@example.com")

			const total = 40
			for i := range total {
				enqueue(t, db, mb, fmt.Sprintf("to-%d@example.net", i))
			}

			const workers = 6
			var (
				wg     sync.WaitGroup
				mu     sync.Mutex
				seen   = map[string]string{}
				dupes  []string
				errsCh = make(chan error, workers)
			)

			for w := range workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					owner := fmt.Sprintf("worker-%d", w)
					for {
						claimed, err := db.Messages().ClaimMessages(t.Context(), owner, 5, time.Minute)
						if err != nil {
							errsCh <- err
							return
						}
						if len(claimed) == 0 {
							return
						}
						mu.Lock()
						for _, m := range claimed {
							if prev, dup := seen[m.ID]; dup {
								dupes = append(dupes, fmt.Sprintf("%s claimed by both %s and %s", m.ID, prev, owner))
							}
							seen[m.ID] = owner
						}
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			close(errsCh)

			for err := range errsCh {
				t.Errorf("worker error: %v", err)
			}
			if len(dupes) > 0 {
				t.Errorf("messages were claimed twice:\n%v", dupes)
			}
			if len(seen) != total {
				t.Errorf("%d of %d messages were claimed", len(seen), total)
			}
		})
	}
}

func TestClaimRespectsLimitAndDueTime(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")

	for range 5 {
		enqueue(t, db, mb, "to@example.net")
	}

	// A message scheduled for the future must not be claimed yet.
	future := &store.Message{
		MailboxID:     store.NullString(mb.ID),
		EnvelopeFrom:  mb.Address,
		Recipients:    []string{"later@example.net"},
		NextAttemptAt: time.Now().UTC().Add(time.Hour),
	}
	if err := db.Messages().Enqueue(t.Context(), future, []byte("body")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	claimed, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 3, time.Minute)
	if err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}
	if len(claimed) != 3 {
		t.Fatalf("claimed %d messages, want the limit of 3", len(claimed))
	}
	for _, m := range claimed {
		if m.ID == future.ID {
			t.Error("claimed a message that is not due yet")
		}
	}

	if _, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 0, time.Minute); err != nil {
		t.Errorf("ClaimMessages with limit 0 = %v, want no error", err)
	}
	if _, err := db.Messages().ClaimMessages(t.Context(), "", 1, time.Minute); err == nil {
		t.Error("ClaimMessages with no worker identity succeeded")
	}
}

// A worker that crashes leaves a lease behind. Once it expires the message must
// become claimable again, or it is stuck forever.
func TestExpiredLeaseIsReclaimed(t *testing.T) {
	t.Parallel()

	for _, driver := range storetest.Drivers() {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()

			db := storetest.Open(t, driver)
			mb := newMailbox(t, db, "shared@example.com")
			m := enqueue(t, db, mb, "to@example.net")

			// A lease that has already expired stands in for a crashed worker.
			claimed, err := db.Messages().ClaimMessages(t.Context(), "dead-worker", 1, -time.Minute)
			if err != nil {
				t.Fatalf("ClaimMessages: %v", err)
			}
			if len(claimed) != 1 {
				t.Fatalf("claimed %d messages, want 1", len(claimed))
			}

			reclaimed, err := db.Messages().ClaimMessages(t.Context(), "live-worker", 1, time.Minute)
			if err != nil {
				t.Fatalf("reclaiming: %v", err)
			}
			if len(reclaimed) != 1 || reclaimed[0].ID != m.ID {
				t.Fatalf("reclaimed %d messages, want the abandoned one", len(reclaimed))
			}

			// The original owner must no longer be able to complete it.
			if err := db.Messages().MarkSent(t.Context(), m.ID, "dead-worker"); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("MarkSent by the previous owner = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestReleaseExpiredLeases(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "to@example.net")

	if _, err := db.Messages().ClaimMessages(t.Context(), "dead-worker", 1, -time.Minute); err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}

	n, err := db.Messages().ReleaseExpiredLeases(t.Context())
	if err != nil {
		t.Fatalf("ReleaseExpiredLeases: %v", err)
	}
	if n != 1 {
		t.Errorf("released %d leases, want 1", n)
	}

	got, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != store.StatusQueued || got.LeaseOwner.Valid {
		t.Errorf("message is %+v, want queued with no lease", got.Status)
	}
}

func TestExtendLease(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "to@example.net")

	claimed, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimMessages = (%d, %v)", len(claimed), err)
	}

	if err := db.Messages().ExtendLease(t.Context(), m.ID, "worker-1", time.Hour); err != nil {
		t.Fatalf("ExtendLease: %v", err)
	}
	got, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.LeaseExpiresAt.Valid || got.LeaseExpiresAt.Time.Before(claimed[0].LeaseExpiresAt.Time) {
		t.Error("ExtendLease did not push the expiry out")
	}

	// Only the holder may extend it.
	if err := db.Messages().ExtendLease(t.Context(), m.ID, "worker-2", time.Hour); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ExtendLease by a non-holder = %v, want ErrNotFound", err)
	}
}

func TestDeferAndFail(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "to@example.net")

	if _, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 1, time.Minute); err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}

	retryAt := time.Now().UTC().Add(5 * time.Minute)
	transient := store.Failure{Code: "4.7.500", Message: "Server busy"}
	if err := db.Messages().Defer(t.Context(), m.ID, "worker-1", transient, retryAt); err != nil {
		t.Fatalf("Defer: %v", err)
	}

	got, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != store.StatusDeferred {
		t.Errorf("Status = %q, want deferred", got.Status)
	}
	if got.Attempts != 1 || got.LastErrorCode != "4.7.500" {
		t.Errorf("got attempts=%d code=%q, want 1 and 4.7.500", got.Attempts, got.LastErrorCode)
	}
	if got.LeaseOwner.Valid {
		t.Error("Defer did not release the lease")
	}

	// A deferred message must not be claimable before its retry time.
	claimed, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}
	if len(claimed) != 0 {
		t.Error("claimed a deferred message before its retry time")
	}

	// Now fail it permanently.
	if err := db.Messages().Requeue(t.Context(), m.ID); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	if _, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 1, time.Minute); err != nil {
		t.Fatalf("ClaimMessages after Requeue: %v", err)
	}
	permanent := store.Failure{Code: "550", Message: "Mailbox unavailable", Permanent: true}
	if err := db.Messages().Fail(t.Context(), m.ID, "worker-1", permanent); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	got, err = db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != store.StatusFailed || !got.LastErrorPermanent {
		t.Errorf("got status=%q permanent=%v, want failed and permanent", got.Status, got.LastErrorPermanent)
	}
}

func TestHoldAndRequeue(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "to@example.net")

	if err := db.Messages().Hold(t.Context(), m.ID); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	claimed, err := db.Messages().ClaimMessages(t.Context(), "worker-1", 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}
	if len(claimed) != 0 {
		t.Error("a held message was claimed for delivery")
	}

	if err := db.Messages().Requeue(t.Context(), m.ID); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	claimed, err = db.Messages().ClaimMessages(t.Context(), "worker-1", 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Errorf("after Requeue, claimed %d messages, want 1 (%v)", len(claimed), err)
	}
}

func TestRequeueRecoversAStuckSendingMessage(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "to@example.net")

	// A very long lease stands in for a worker that is wedged rather than dead.
	if _, err := db.Messages().ClaimMessages(t.Context(), "wedged", 1, 24*time.Hour); err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}
	// An operator must be able to rescue it from the admin UI without waiting.
	if err := db.Messages().Requeue(t.Context(), m.ID); err != nil {
		t.Fatalf("Requeue of a sending message: %v", err)
	}
	got, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != store.StatusQueued || got.LeaseOwner.Valid {
		t.Errorf("message is %q with lease %+v, want queued and unleased", got.Status, got.LeaseOwner)
	}
}

func TestDeleteRemovesTheBody(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "to@example.net")

	if err := db.Messages().Delete(t.Context(), m.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := db.Messages().Body(t.Context(), m.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the body survived the message: %v", err)
	}
}

func TestPurgeOnlyRemovesFinishedMessages(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")

	sent := enqueue(t, db, mb, "sent@example.net")
	if _, err := db.Messages().ClaimMessages(t.Context(), "w", 1, time.Minute); err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}
	if err := db.Messages().MarkSent(t.Context(), sent.ID, "w"); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	queued := enqueue(t, db, mb, "queued@example.net")

	// Nothing is old enough yet.
	n, err := db.Messages().Purge(t.Context(), time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 0 {
		t.Errorf("purged %d recent messages, want 0", n)
	}

	n, err = db.Messages().Purge(t.Context(), time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purged %d messages, want only the sent one", n)
	}
	if _, err := db.Messages().Get(t.Context(), queued.ID); err != nil {
		t.Errorf("the queued message was purged: %v", err)
	}
}

func TestListAndCount(t *testing.T) {
	// Not parallel: the subtests below share one database and must not race.
	db := storetest.Open(t, store.DriverSQLite)
	sales := newMailbox(t, db, "sales@example.com")
	support := newMailbox(t, db, "support@example.com")

	enqueue(t, db, sales, "one@example.net")
	enqueue(t, db, sales, "two@example.net")
	enqueue(t, db, support, "three@example.net")

	tests := []struct {
		name   string
		filter store.MessageFilter
		want   int
	}{
		{"no filter", store.MessageFilter{}, 3},
		{"by mailbox", store.MessageFilter{MailboxID: sales.ID}, 2},
		{"by status", store.MessageFilter{Status: []store.MessageStatus{store.StatusQueued}}, 3},
		{"by absent status", store.MessageFilter{Status: []store.MessageStatus{store.StatusSent}}, 0},
		{"by recipient search", store.MessageFilter{Search: "three@"}, 1},
		{"by sender search", store.MessageFilter{Search: "sales@example.com"}, 2},
		{"since the future", store.MessageFilter{Since: time.Now().Add(time.Hour)}, 0},
		{"until the past", store.MessageFilter{Until: time.Now().Add(-time.Hour)}, 0},
		{"limit", store.MessageFilter{Limit: 2}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.Messages().List(t.Context(), tt.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("List returned %d messages, want %d", len(got), tt.want)
			}
		})
	}

	total, err := db.Messages().Count(t.Context(), store.MessageFilter{MailboxID: sales.ID})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 2 {
		t.Errorf("Count = %d, want 2", total)
	}

	// Count must ignore the limit, so pagination can report a real total.
	total, err = db.Messages().Count(t.Context(), store.MessageFilter{Limit: 1})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 3 {
		t.Errorf("Count with a limit = %d, want the unpaginated total of 3", total)
	}
}

func TestCountByStatus(t *testing.T) {
	t.Parallel()

	db := storetest.Open(t, store.DriverSQLite)
	mb := newMailbox(t, db, "shared@example.com")
	m := enqueue(t, db, mb, "one@example.net")
	enqueue(t, db, mb, "two@example.net")

	if _, err := db.Messages().ClaimMessages(t.Context(), "w", 1, time.Minute); err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}
	if err := db.Messages().MarkSent(t.Context(), m.ID, "w"); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}

	counts, err := db.Messages().CountByStatus(t.Context())
	if err != nil {
		t.Fatalf("CountByStatus: %v", err)
	}
	if counts[store.StatusSent] != 1 || counts[store.StatusQueued] != 1 {
		t.Errorf("CountByStatus = %v, want one sent and one queued", counts)
	}
}
