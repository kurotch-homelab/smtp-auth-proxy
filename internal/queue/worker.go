package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
)

// Options configure the delivery workers.
type Options struct {
	DB *store.DB
	// Transports maps a mailbox's transport name to its implementation.
	Transports map[store.Transport]transport.Transport

	// Workers is how many deliveries run concurrently across all mailboxes.
	Workers int
	// PollInterval is how often an idle worker looks for new work.
	PollInterval time.Duration
	// LeaseDuration is how long a worker owns a claimed message. It must exceed
	// the upstream timeout, or another replica could start delivering a message
	// that is still in flight.
	LeaseDuration time.Duration

	Backoff Backoff
	Budget  Budget

	// Retention prunes finished messages.
	RetainSent    time.Duration
	RetainFailed  time.Duration
	PurgeInterval time.Duration

	// WorkerID identifies this process in the lease. Defaults to a random value,
	// which is what a Kubernetes rollout needs: two replicas must never share
	// an identity or they would steal each other's leases.
	WorkerID string
	// Recorder receives metrics; nil disables them.
	Recorder Recorder
	Log      *slog.Logger
	// now is injectable for tests.
	now func() time.Time
}

// Runner delivers queued messages until it is stopped.
type Runner struct {
	opts    Options
	limiter *Limiter
	log     *slog.Logger

	// bodies loads a message's MIME content. Kept as a field so a filesystem
	// spool can be substituted later.
	bodies func(ctx context.Context, id string) ([]byte, error)

	mu      sync.Mutex
	running bool
}

// New returns a Runner.
func New(opts Options) (*Runner, error) {
	if opts.DB == nil {
		return nil, errors.New("queue: a database is required")
	}
	if len(opts.Transports) == 0 {
		return nil, errors.New("queue: at least one transport is required")
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.LeaseDuration <= 0 {
		opts.LeaseDuration = 5 * time.Minute
	}
	if opts.PurgeInterval <= 0 {
		opts.PurgeInterval = time.Hour
	}
	if opts.WorkerID == "" {
		opts.WorkerID = store.NewID()
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Recorder == nil {
		opts.Recorder = nopRecorder{}
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	r := &Runner{
		opts:    opts,
		limiter: NewLimiter(opts.Budget),
		log:     opts.Log.With("worker_id", opts.WorkerID),
	}
	r.bodies = opts.DB.Messages().Body
	return r, nil
}

// Run delivers messages until ctx is done.
func (r *Runner) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("queue: already running")
	}
	r.running = true
	r.mu.Unlock()

	r.log.Info("queue workers started",
		"workers", r.opts.Workers,
		"poll_interval", r.opts.PollInterval,
		"lease", r.opts.LeaseDuration)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.housekeeping(ctx)
	}()

	// One dispatcher claims work and hands it to a bounded pool. Claiming from
	// a single place keeps the number of database round trips proportional to
	// throughput rather than to the number of workers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.dispatch(ctx)
	}()

	wg.Wait()

	r.mu.Lock()
	r.running = false
	r.mu.Unlock()

	r.log.Info("queue workers stopped")
	return nil
}

func (r *Runner) dispatch(ctx context.Context) {
	slots := make(chan struct{}, r.opts.Workers)
	var inFlight sync.WaitGroup
	defer inFlight.Wait()

	ticker := time.NewTicker(r.opts.PollInterval)
	defer ticker.Stop()

	for {
		claimed := r.claim(ctx, cap(slots)-len(slots))

		for _, m := range claimed {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}

			inFlight.Add(1)
			go func() {
				defer inFlight.Done()
				defer func() { <-slots }()
				r.deliver(ctx, m)
			}()
		}

		// Only wait when there was nothing to do; a full batch means there is
		// probably more waiting.
		if len(claimed) > 0 {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) claim(ctx context.Context, limit int) []*store.Message {
	if limit <= 0 {
		return nil
	}

	claimed, err := r.opts.DB.Messages().ClaimMessages(ctx, r.opts.WorkerID, limit, r.opts.LeaseDuration)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("could not claim messages", "reason", err)
		}
		return nil
	}
	return claimed
}

// deliver sends one message and records the outcome.
func (r *Runner) deliver(ctx context.Context, m *store.Message) {
	log := r.log.With("message_id", m.ID, "mailbox", m.MailboxAddress, "attempt", m.Attempts+1)

	prepared, err := r.prepare(ctx, m)
	if err != nil {
		// The message cannot be delivered as it stands and no upstream was
		// involved, so this is final: retrying would fail the same way.
		r.recordFailure(ctx, log, m, transport.NewPermanent("proxy", err.Error(), err))
		return
	}

	budget := Budget{
		PerMinute:     int(prepared.Mailbox.RateLimitPerMin.Int64),
		MaxConcurrent: int(prepared.Mailbox.MaxConcurrent.Int64),
	}
	release, err := r.limiter.Acquire(ctx, prepared.Mailbox.ID, budget)
	if err != nil {
		// Shutting down; leave the message claimed and let the lease expire so
		// another worker picks it up promptly.
		return
	}
	defer release()

	backend, ok := r.opts.Transports[prepared.Mailbox.Transport]
	if !ok {
		r.recordFailure(ctx, log, m, transport.NewPermanent("proxy",
			fmt.Sprintf("no transport is configured for %q", prepared.Mailbox.Transport), nil))
		return
	}

	start := r.opts.now()
	sendErr := backend.Send(ctx, prepared)
	elapsed := r.opts.now().Sub(start)

	if sendErr == nil {
		r.opts.Recorder.Delivery(backend.Name(), DeliverySent, elapsed)
		if err := r.opts.DB.Messages().MarkSent(ctx, m.ID, r.opts.WorkerID); err != nil {
			// The message was delivered. Failing to record that means it will be
			// retried and the recipient will see it twice, so it is worth an
			// error-level log even though nothing here can fix it.
			log.Error("delivered a message but could not record it as sent",
				"reason", err, "duration", elapsed)
			return
		}
		log.Info("delivered", "transport", backend.Name(), "duration", elapsed,
			"recipients", len(m.Recipients))
		return
	}

	r.recordFailure(ctx, log.With("transport", backend.Name(), "duration", elapsed), m, sendErr)
	r.opts.Recorder.Delivery(backend.Name(), outcomeFor(sendErr), elapsed)
}

// prepare loads everything a delivery needs.
func (r *Runner) prepare(ctx context.Context, m *store.Message) (*transport.Message, error) {
	if !m.MailboxID.Valid {
		return nil, errors.New("the message is not associated with a mailbox")
	}

	mailbox, err := r.opts.DB.Mailboxes().Get(ctx, m.MailboxID.String)
	if err != nil {
		return nil, fmt.Errorf("loading the mailbox: %w", err)
	}
	if !mailbox.Enabled {
		return nil, fmt.Errorf("the mailbox %s is disabled", mailbox.Address)
	}

	credential, err := r.opts.DB.Credentials().Get(ctx, mailbox.OAuthCredentialID)
	if err != nil {
		return nil, fmt.Errorf("loading the credential for %s: %w", mailbox.Address, err)
	}

	body, err := r.bodies(ctx, m.ID)
	if err != nil {
		return nil, fmt.Errorf("loading the message body: %w", err)
	}

	return &transport.Message{
		ID:         m.ID,
		Mailbox:    mailbox,
		Credential: credential,
		Recipients: m.Recipients,
		Raw:        body,
	}, nil
}

// recordFailure decides whether to retry and writes the outcome.
func (r *Runner) recordFailure(ctx context.Context, log *slog.Logger, m *store.Message, sendErr error) {
	failure := transport.AsFailure(sendErr)
	attempts := m.Attempts + 1

	if transport.IsPermanent(sendErr) {
		if err := r.opts.DB.Messages().Fail(ctx, m.ID, r.opts.WorkerID, failure); err != nil {
			log.Error("could not record a permanent failure", "reason", err)
			return
		}
		log.Warn("permanently failed", "code", failure.Code, "reason", failure.Message)
		return
	}

	retryAt, retry := r.opts.Backoff.NextAttemptAfter(
		r.opts.now(), attempts, m.ReceivedAt, transport.RetryAfter(sendErr))
	if !retry {
		failure.Permanent = true
		failure.Message = fmt.Sprintf("giving up after %d attempts: %s", attempts, failure.Message)
		if err := r.opts.DB.Messages().Fail(ctx, m.ID, r.opts.WorkerID, failure); err != nil {
			log.Error("could not record a give-up", "reason", err)
			return
		}
		log.Warn("gave up", "code", failure.Code, "attempts", attempts, "reason", failure.Message)
		return
	}

	if err := r.opts.DB.Messages().Defer(ctx, m.ID, r.opts.WorkerID, failure, retryAt); err != nil {
		log.Error("could not defer a message", "reason", err)
		return
	}

	// An authentication failure means the tenant configuration is wrong and
	// every mailbox on that credential is affected, so it is logged louder than
	// an ordinary delivery problem.
	level := slog.LevelInfo
	if transport.IsAuthFailure(sendErr) {
		level = slog.LevelWarn
	}
	log.Log(ctx, level, "deferred",
		"code", failure.Code, "retry_at", retryAt, "reason", failure.Message)
}

// outcomeFor labels a failed delivery by whether it will be retried.
func outcomeFor(err error) string {
	if transport.IsPermanent(err) {
		return DeliveryFailed
	}
	return DeliveryDeferred
}

// publishGauges reports queue depth and credential expiry.
//
// These are the numbers worth alerting on: a queue that stops draining means
// mail is not being delivered whatever the error counters say, and a credential
// quietly expiring is the most common way a working deployment breaks.
func (r *Runner) publishGauges(ctx context.Context) {
	counts, err := r.opts.DB.Messages().CountByStatus(ctx)
	if err == nil {
		// Every status is published, including the ones at zero, so a gauge
		// that drops to nothing is visible rather than simply absent.
		for _, status := range []store.MessageStatus{
			store.StatusQueued, store.StatusSending, store.StatusDeferred,
			store.StatusFailed, store.StatusHeld, store.StatusSent,
		} {
			r.opts.Recorder.QueueDepth(string(status), float64(counts[status]))
		}
	} else if ctx.Err() == nil {
		r.log.Warn("could not publish queue depth", "reason", err)
	}

	credentials, err := r.opts.DB.Credentials().List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("could not publish credential expiry", "reason", err)
		}
		return
	}
	for _, c := range credentials {
		if !c.ExpiresAt.Valid {
			continue
		}
		r.opts.Recorder.CredentialExpiry(c.Name, time.Until(c.ExpiresAt.Time).Seconds())
	}
}

// housekeeping releases abandoned leases and prunes finished messages.
func (r *Runner) housekeeping(ctx context.Context) {
	ticker := time.NewTicker(r.opts.PurgeInterval)
	defer ticker.Stop()

	// Reclaim on start: a crash leaves messages in `sending`, and an operator
	// watching the queue should not have to wait an hour to see them recover.
	r.releaseExpiredLeases(ctx)
	r.publishGauges(ctx)

	// Gauges refresh far more often than the purge: a dashboard showing an
	// hour-old queue depth is worse than none.
	gauges := time.NewTicker(gaugeInterval)
	defer gauges.Stop()

	for {
		select {
		case <-gauges.C:
			r.publishGauges(ctx)
		case <-ticker.C:
			r.releaseExpiredLeases(ctx)
			r.purge(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// gaugeInterval is how often queue depth and credential expiry are refreshed.
const gaugeInterval = 15 * time.Second

func (r *Runner) releaseExpiredLeases(ctx context.Context) {
	n, err := r.opts.DB.Messages().ReleaseExpiredLeases(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("could not release expired leases", "reason", err)
		}
		return
	}
	if n > 0 {
		r.log.Info("released leases from workers that did not finish", "messages", n)
	}
}

func (r *Runner) purge(ctx context.Context) {
	if r.opts.RetainSent <= 0 && r.opts.RetainFailed <= 0 {
		return
	}

	now := r.opts.now()
	sentBefore := now.Add(-r.opts.RetainSent)
	failedBefore := now.Add(-r.opts.RetainFailed)

	n, err := r.opts.DB.Messages().Purge(ctx, sentBefore, failedBefore)
	if err != nil {
		if ctx.Err() == nil {
			r.log.Error("could not purge old messages", "reason", err)
		}
		return
	}
	if n > 0 {
		r.log.Info("purged finished messages", "messages", n)
	}
}
