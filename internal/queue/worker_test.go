package queue_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/queue"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/storetest"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
)

// recordingTransport captures deliveries and can be told to fail.
type recordingTransport struct {
	mu        sync.Mutex
	delivered []*transport.Message
	// err, when set, is returned instead of delivering.
	err error
	// failFirst makes the first n attempts fail with err, then succeed.
	failFirst int
	attempts  int
	// block, when non-nil, holds each delivery until it is closed.
	block chan struct{}
}

func (r *recordingTransport) Name() string { return "fake" }

func (r *recordingTransport) Send(ctx context.Context, m *transport.Message) error {
	r.mu.Lock()
	r.attempts++
	attempt := r.attempts
	err := r.err
	failFirst := r.failFirst
	block := r.block
	r.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err != nil && (failFirst == 0 || attempt <= failFirst) {
		return err
	}

	r.mu.Lock()
	r.delivered = append(r.delivered, m)
	r.mu.Unlock()
	return nil
}

func (r *recordingTransport) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.delivered)
}

func (r *recordingTransport) last() *transport.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.delivered) == 0 {
		return nil
	}
	return r.delivered[len(r.delivered)-1]
}

// fixtures builds a mailbox with a credential and returns the database.
func fixtures(t *testing.T) (*store.DB, *store.Mailbox) {
	t.Helper()

	db := storetest.Open(t, store.DriverSQLite)

	cred := &store.OAuthCredential{
		Name: "primary", TenantID: "tenant", ClientID: "client",
		AuthType: store.AuthTypeSecret, ClientSecretEnc: "v1.k1.sealed",
	}
	if err := db.Credentials().Create(t.Context(), cred); err != nil {
		t.Fatalf("creating a credential: %v", err)
	}

	mb := &store.Mailbox{
		Address: "shared@example.com", OAuthCredentialID: cred.ID,
		Transport: store.TransportSMTP, Enabled: true,
	}
	if err := db.Mailboxes().Create(t.Context(), mb); err != nil {
		t.Fatalf("creating a mailbox: %v", err)
	}
	return db, mb
}

func enqueue(t *testing.T, db *store.DB, mb *store.Mailbox, to string) *store.Message {
	t.Helper()

	m := &store.Message{
		MailboxID:      store.NullString(mb.ID),
		MailboxAddress: mb.Address,
		EnvelopeFrom:   mb.Address,
		Recipients:     []string{to},
		NextAttemptAt:  time.Now().UTC().Add(-time.Second),
	}
	if err := db.Messages().Enqueue(t.Context(), m, []byte("Subject: test\r\n\r\nbody")); err != nil {
		t.Fatalf("enqueueing: %v", err)
	}
	return m
}

// runner builds a Runner over a transport, with fast polling for tests.
func runner(t *testing.T, db *store.DB, tr transport.Transport, mutate func(*queue.Options)) *queue.Runner {
	t.Helper()

	opts := queue.Options{
		DB:            db,
		Transports:    map[store.Transport]transport.Transport{store.TransportSMTP: tr},
		Workers:       4,
		PollInterval:  10 * time.Millisecond,
		LeaseDuration: time.Minute,
		PurgeInterval: time.Hour,
		Backoff: queue.Backoff{
			Delays:      []time.Duration{time.Millisecond},
			MaxAttempts: 3,
			MaxAge:      time.Hour,
		},
		Budget:   queue.Budget{PerMinute: queue.ExchangeMessagesPerMinute, MaxConcurrent: 3},
		WorkerID: "test-worker",
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&opts)
	}

	r, err := queue.New(opts)
	if err != nil {
		t.Fatalf("queue.New: %v", err)
	}
	return r
}

// run starts a Runner and stops it with the test.
func run(t *testing.T, r *queue.Runner) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Run(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("the runner did not stop")
		}
	})
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func statusOf(t *testing.T, db *store.DB, id string) store.MessageStatus {
	t.Helper()

	m, err := db.Messages().Get(t.Context(), id)
	if err != nil {
		t.Fatalf("reading message %s: %v", id, err)
	}
	return m.Status
}

func TestRunnerDeliversAQueuedMessage(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to be delivered", func() bool { return tr.count() == 1 })
	waitFor(t, "the message to be marked sent", func() bool {
		return statusOf(t, db, m.ID) == store.StatusSent
	})

	delivered := tr.last()
	if delivered.Mailbox.Address != "shared@example.com" {
		t.Errorf("delivered as %q, want the mailbox address", delivered.Mailbox.Address)
	}
	if delivered.Credential == nil || delivered.Credential.Name != "primary" {
		t.Errorf("the credential was not loaded: %+v", delivered.Credential)
	}
	if string(delivered.Raw) != "Subject: test\r\n\r\nbody" {
		t.Errorf("the body was not loaded: %q", delivered.Raw)
	}
}

func TestRunnerRetriesATransientFailure(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	// Fail twice with the throttling response Exchange sends, then succeed.
	tr := &recordingTransport{
		err:       transport.NewTransient("4.7.500", "Server busy", nil),
		failFirst: 2,
	}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to be delivered after retries", func() bool {
		return statusOf(t, db, m.ID) == store.StatusSent
	})

	final, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3", final.Attempts)
	}
}

func TestRunnerFailsPermanentlyWithoutRetrying(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	tr := &recordingTransport{err: transport.NewPermanent("5.1.1", "User unknown", nil)}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to fail", func() bool {
		return statusOf(t, db, m.ID) == store.StatusFailed
	})

	final, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// A permanent rejection must not burn through the retry schedule.
	if final.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1 for a permanent failure", final.Attempts)
	}
	if !final.LastErrorPermanent {
		t.Error("the failure was not recorded as permanent")
	}
	if final.LastErrorCode != "5.1.1" {
		t.Errorf("LastErrorCode = %q", final.LastErrorCode)
	}
}

func TestRunnerGivesUpAfterMaxAttempts(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	tr := &recordingTransport{err: transport.NewTransient("4.3.2", "Try later", nil)}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to be given up on", func() bool {
		return statusOf(t, db, m.ID) == store.StatusFailed
	})

	final, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.Attempts != 3 {
		t.Errorf("Attempts = %d, want the configured maximum of 3", final.Attempts)
	}
	// Giving up is recorded as permanent so the queue view does not imply the
	// message is still waiting for something.
	if !final.LastErrorPermanent {
		t.Error("giving up was not recorded as permanent")
	}
}

func TestRunnerSkipsAMessageWithNoMailbox(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	// Deleting the mailbox nulls the reference but keeps the history.
	if err := db.Mailboxes().Delete(t.Context(), mb.ID); err != nil {
		t.Fatalf("deleting the mailbox: %v", err)
	}

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the orphaned message to fail", func() bool {
		return statusOf(t, db, m.ID) == store.StatusFailed
	})
	if tr.count() != 0 {
		t.Error("a message with no mailbox was sent anyway")
	}
}

func TestRunnerRefusesADisabledMailbox(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	mb.Enabled = false
	if err := db.Mailboxes().Update(t.Context(), mb); err != nil {
		t.Fatalf("disabling the mailbox: %v", err)
	}

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to fail", func() bool {
		return statusOf(t, db, m.ID) == store.StatusFailed
	})
	if tr.count() != 0 {
		t.Error("a disabled mailbox still sent mail")
	}
}

func TestRunnerFailsWhenNoTransportIsConfigured(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)

	// A mailbox set to Graph in a build with only the SMTP transport wired up.
	mb.Transport = store.TransportGraph
	if err := db.Mailboxes().Update(t.Context(), mb); err != nil {
		t.Fatalf("Update: %v", err)
	}
	m := enqueue(t, db, mb, "ops@example.net")

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to fail", func() bool {
		return statusOf(t, db, m.ID) == store.StatusFailed
	})
	if tr.count() != 0 {
		t.Error("the message went out through the wrong transport")
	}
}

func TestRunnerHonorsPerMailboxConcurrency(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)

	// Exchange Online allows three concurrent submissions per mailbox; pin this
	// mailbox to one and prove nothing overlaps.
	mb.MaxConcurrent = store.NullInt(1)
	if err := db.Mailboxes().Update(t.Context(), mb); err != nil {
		t.Fatalf("Update: %v", err)
	}

	for range 4 {
		enqueue(t, db, mb, "ops@example.net")
	}

	var (
		mu      sync.Mutex
		inUse   int
		maxSeen int
	)
	tr := &countingTransport{onSend: func() {
		mu.Lock()
		inUse++
		if inUse > maxSeen {
			maxSeen = inUse
		}
		mu.Unlock()

		time.Sleep(20 * time.Millisecond)

		mu.Lock()
		inUse--
		mu.Unlock()
	}}

	run(t, runner(t, db, tr, nil))
	waitFor(t, "all four messages to be delivered", func() bool { return tr.count() == 4 })

	mu.Lock()
	defer mu.Unlock()
	if maxSeen > 1 {
		t.Errorf("%d deliveries overlapped, want at most 1", maxSeen)
	}
}

func TestRunnerReleasesLeasesFromACrashedWorker(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	// A lease left behind by a worker that never came back.
	if _, err := db.Messages().ClaimMessages(t.Context(), "dead-worker", 1, -time.Minute); err != nil {
		t.Fatalf("ClaimMessages: %v", err)
	}

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, nil))

	// An operator watching the queue should not have to wait for a purge cycle.
	waitFor(t, "the abandoned message to be delivered", func() bool {
		return statusOf(t, db, m.ID) == store.StatusSent
	})
}

func TestRunnerPurgesFinishedMessages(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, func(o *queue.Options) {
		o.PurgeInterval = 20 * time.Millisecond
		// Retain nothing, so anything finished is eligible immediately.
		o.RetainSent = time.Nanosecond
		o.RetainFailed = time.Nanosecond
	}))

	waitFor(t, "the message to be purged", func() bool {
		_, err := db.Messages().Get(t.Context(), m.ID)
		return errors.Is(err, store.ErrNotFound)
	})
}

func TestRunnerStopsCleanly(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	enqueue(t, db, mb, "ops@example.net")

	// A delivery that never finishes on its own; shutdown must not wait for it
	// indefinitely.
	block := make(chan struct{})
	tr := &recordingTransport{block: block}
	r := runner(t, db, tr, nil)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	close(block)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context was canceled")
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()

	db, _ := fixtures(t)
	tr := &recordingTransport{}

	if _, err := queue.New(queue.Options{Transports: map[store.Transport]transport.Transport{store.TransportSMTP: tr}}); err == nil {
		t.Error("New accepted options with no database")
	}
	if _, err := queue.New(queue.Options{DB: db}); err == nil {
		t.Error("New accepted options with no transports")
	}
}

// countingTransport runs a callback on every send.
type countingTransport struct {
	onSend func()
	mu     sync.Mutex
	sent   int
}

func (c *countingTransport) Name() string { return "counting" }

func (c *countingTransport) Send(context.Context, *transport.Message) error {
	if c.onSend != nil {
		c.onSend()
	}
	c.mu.Lock()
	c.sent++
	c.mu.Unlock()
	return nil
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

func TestRunnerRefusesToRunTwice(t *testing.T) {
	t.Parallel()

	db, _ := fixtures(t)
	r := runner(t, db, &recordingTransport{}, nil)
	run(t, r)

	// Two Run calls on one Runner would give both loops the same worker
	// identity, so each could steal the other's leases.
	time.Sleep(50 * time.Millisecond)
	if err := r.Run(t.Context()); err == nil {
		t.Error("a second Run was allowed on the same Runner")
	}
}

func TestRunnerAppliesDefaultsToOptions(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	// Only the mandatory fields; everything else should get a working default,
	// including a worker identity, which two replicas must never share.
	tr := &recordingTransport{}
	r, err := queue.New(queue.Options{
		DB:           db,
		Transports:   map[store.Transport]transport.Transport{store.TransportSMTP: tr},
		PollInterval: 10 * time.Millisecond,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("queue.New: %v", err)
	}
	run(t, r)

	waitFor(t, "the message to be delivered with default options", func() bool {
		return statusOf(t, db, m.ID) == store.StatusSent
	})
}

func TestRunnerHonorsAnUpstreamRetryAfter(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	// The upstream asked for far longer than the schedule, so the message must
	// still be waiting rather than retried immediately.
	tr := &recordingTransport{
		err: transport.NewThrottled("429", "Too many requests", time.Hour, nil),
	}
	run(t, runner(t, db, tr, nil))

	waitFor(t, "the message to be deferred", func() bool {
		return statusOf(t, db, m.ID) == store.StatusDeferred
	})

	deferred, err := db.Messages().Get(t.Context(), m.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if until := time.Until(deferred.NextAttemptAt); until < 50*time.Minute {
		t.Errorf("the next attempt is in %v, want about the hour the upstream asked for", until)
	}
}

func TestRunnerPurgeIsSkippedWithoutRetention(t *testing.T) {
	t.Parallel()

	db, mb := fixtures(t)
	m := enqueue(t, db, mb, "ops@example.net")

	tr := &recordingTransport{}
	run(t, runner(t, db, tr, func(o *queue.Options) {
		o.PurgeInterval = 20 * time.Millisecond
		// Retention unset means keep everything.
		o.RetainSent = 0
		o.RetainFailed = 0
	}))

	waitFor(t, "the message to be sent", func() bool {
		return statusOf(t, db, m.ID) == store.StatusSent
	})

	// Give the purge loop several chances to run before checking.
	time.Sleep(150 * time.Millisecond)
	if _, err := db.Messages().Get(t.Context(), m.ID); err != nil {
		t.Errorf("a message was purged even though retention was not configured: %v", err)
	}
}
