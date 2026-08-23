package queue

import (
	"context"
	"sync"
	"time"
)

// Exchange Online's published limits for SMTP client submission, per mailbox.
// The proxy stays under both rather than discovering them at delivery time.
const (
	// ExchangeMessagesPerMinute is the sustained message rate a mailbox is
	// allowed. Exceeding it produces "4.7.500 Server busy".
	ExchangeMessagesPerMinute = 30
	// ExchangeConcurrentConnections is how many submissions a mailbox may have
	// in flight. The default stays below it so a retry always has room.
	ExchangeConcurrentConnections = 3
)

// mailboxLimiter paces deliveries for one mailbox: a token bucket for the rate
// and a semaphore for concurrency.
type mailboxLimiter struct {
	bucket    *tokenBucket
	semaphore chan struct{}
}

// Limiter holds the per-mailbox budgets.
type Limiter struct {
	mu       sync.Mutex
	mailbox  map[string]*mailboxLimiter
	now      func() time.Time
	defaults Budget
}

// Budget is one mailbox's allowance.
type Budget struct {
	PerMinute     int
	MaxConcurrent int
}

// clamp brings a budget within what Exchange Online actually permits, because
// a value above the limit is not a preference the upstream will honor.
func (b Budget) clamp() Budget {
	if b.PerMinute <= 0 || b.PerMinute > ExchangeMessagesPerMinute {
		b.PerMinute = ExchangeMessagesPerMinute
	}
	if b.MaxConcurrent <= 0 {
		b.MaxConcurrent = 2
	}
	if b.MaxConcurrent > ExchangeConcurrentConnections {
		b.MaxConcurrent = ExchangeConcurrentConnections
	}
	return b
}

// NewLimiter returns a limiter with the given defaults.
func NewLimiter(defaults Budget) *Limiter {
	return &Limiter{
		mailbox:  make(map[string]*mailboxLimiter),
		now:      time.Now,
		defaults: defaults.clamp(),
	}
}

// Acquire waits until the mailbox may send another message, and returns the
// function that releases its concurrency slot.
//
// It returns an error only if ctx is canceled first, so a shutdown does not
// hang behind a rate limit.
func (l *Limiter) Acquire(ctx context.Context, mailboxID string, budget Budget) (release func(), err error) {
	ml := l.forMailbox(mailboxID, budget)

	// Concurrency first: holding a rate token while blocked on a slot would
	// waste the token if the context is canceled.
	select {
	case ml.semaphore <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if err := ml.bucket.wait(ctx, l.now); err != nil {
		<-ml.semaphore
		return nil, err
	}

	var once sync.Once
	return func() { once.Do(func() { <-ml.semaphore }) }, nil
}

func (l *Limiter) forMailbox(id string, budget Budget) *mailboxLimiter {
	effective := l.effective(budget)

	l.mu.Lock()
	defer l.mu.Unlock()

	ml, ok := l.mailbox[id]
	if ok && ml.bucket.perMinute == effective.PerMinute && cap(ml.semaphore) == effective.MaxConcurrent {
		return ml
	}
	// A changed budget rebuilds the limiter. In-flight deliveries hold a slot
	// on the old semaphore and release it there, which is harmless: the new one
	// starts empty and the old one is dropped once they finish.
	ml = &mailboxLimiter{
		bucket:    newTokenBucket(effective.PerMinute, l.now()),
		semaphore: make(chan struct{}, effective.MaxConcurrent),
	}
	l.mailbox[id] = ml
	return ml
}

// effective merges a mailbox's overrides with the defaults.
func (l *Limiter) effective(budget Budget) Budget {
	if budget.PerMinute <= 0 {
		budget.PerMinute = l.defaults.PerMinute
	}
	if budget.MaxConcurrent <= 0 {
		budget.MaxConcurrent = l.defaults.MaxConcurrent
	}
	return budget.clamp()
}

// Forget drops a mailbox's budget, for when it is deleted.
func (l *Limiter) Forget(mailboxID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.mailbox, mailboxID)
}

// tokenBucket refills continuously at perMinute tokens a minute, so a burst
// after an idle period is allowed up to the bucket's capacity but the sustained
// rate stays within budget.
type tokenBucket struct {
	mu        sync.Mutex
	perMinute int
	tokens    float64
	capacity  float64
	last      time.Time
}

func newTokenBucket(perMinute int, now time.Time) *tokenBucket {
	capacity := float64(perMinute)
	return &tokenBucket{
		perMinute: perMinute,
		tokens:    capacity,
		capacity:  capacity,
		last:      now,
	}
}

// wait blocks until a token is available or ctx is done.
func (b *tokenBucket) wait(ctx context.Context, now func() time.Time) error {
	for {
		delay, ok := b.take(now())
		if ok {
			return nil
		}

		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

// take consumes a token if one is available, otherwise reports how long to wait.
func (b *tokenBucket) take(now time.Time) (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill(now)
	if b.tokens >= 1 {
		b.tokens--
		return 0, true
	}

	// Time until the next whole token.
	missing := 1 - b.tokens
	perToken := time.Minute / time.Duration(b.perMinute)
	return time.Duration(missing * float64(perToken)), false
}

func (b *tokenBucket) refill(now time.Time) {
	if !now.After(b.last) {
		return
	}
	elapsed := now.Sub(b.last)
	b.last = now

	b.tokens += elapsed.Minutes() * float64(b.perMinute)
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}
