package queue

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetClampsToExchangeLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Budget
		want Budget
	}{
		{
			// A value above what Exchange Online permits is not a preference it
			// will honor; it just produces "4.7.500 Server busy".
			name: "above the published limits",
			in:   Budget{PerMinute: 1000, MaxConcurrent: 50},
			want: Budget{PerMinute: ExchangeMessagesPerMinute, MaxConcurrent: ExchangeConcurrentConnections},
		},
		{
			name: "within the limits is left alone",
			in:   Budget{PerMinute: 10, MaxConcurrent: 1},
			want: Budget{PerMinute: 10, MaxConcurrent: 1},
		},
		{
			name: "zero means the default",
			in:   Budget{},
			want: Budget{PerMinute: ExchangeMessagesPerMinute, MaxConcurrent: 2},
		},
		{
			name: "negative means the default",
			in:   Budget{PerMinute: -5, MaxConcurrent: -1},
			want: Budget{PerMinute: ExchangeMessagesPerMinute, MaxConcurrent: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.in.clamp(); got != tt.want {
				t.Errorf("clamp() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLimiterCapsConcurrency(t *testing.T) {
	t.Parallel()

	l := NewLimiter(Budget{PerMinute: ExchangeMessagesPerMinute, MaxConcurrent: 2})

	first, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 2})
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	second, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 2})
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}

	// A third must block until one of the first two finishes.
	blocked := make(chan struct{})
	go func() {
		release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 2})
		if err == nil {
			release()
		}
		close(blocked)
	}()

	select {
	case <-blocked:
		t.Fatal("a third concurrent delivery was allowed past the limit of 2")
	case <-time.After(50 * time.Millisecond):
	}

	first()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("releasing a slot did not unblock the waiting delivery")
	}
	second()
}

func TestLimiterIsPerMailbox(t *testing.T) {
	t.Parallel()

	l := NewLimiter(Budget{PerMinute: ExchangeMessagesPerMinute, MaxConcurrent: 1})

	release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	// Exchange's limits are per mailbox, so another mailbox must not be held up
	// by this one.
	done := make(chan struct{})
	go func() {
		r, err := l.Acquire(t.Context(), "mb-2", Budget{MaxConcurrent: 1})
		if err == nil {
			r()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("one mailbox's concurrency limit blocked a different mailbox")
	}
}

func TestLimiterRespectsTheRate(t *testing.T) {
	t.Parallel()

	// The budget is the Exchange Online ceiling; asking for more would be
	// clamped back to this anyway.
	const perMinute = ExchangeMessagesPerMinute
	l := NewLimiter(Budget{PerMinute: perMinute, MaxConcurrent: 10})

	// A frozen clock keeps the test fast while still exercising the real refill
	// arithmetic: with no time passing, no token can come back.
	var nowNanos atomic.Int64
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowNanos.Store(start.UnixNano())
	l.now = func() time.Time { return time.Unix(0, nowNanos.Load()) }

	budget := Budget{PerMinute: perMinute, MaxConcurrent: 10}

	// The bucket starts full, so a minute's worth goes straight through.
	for i := range perMinute {
		release, err := l.Acquire(t.Context(), "mb-1", budget)
		if err != nil {
			t.Fatalf("Acquire %d: %v", i, err)
		}
		release()
	}

	// The next one has to wait for a refill. Canceling proves it was blocked
	// rather than admitted.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	if _, err := l.Acquire(ctx, "mb-1", budget); err == nil {
		t.Error("the rate limit admitted a message past the budget")
	}
}

func TestLimiterUnblocksOnContextCancellation(t *testing.T) {
	t.Parallel()

	// A shutdown must not hang behind a rate limit.
	l := NewLimiter(Budget{PerMinute: 30, MaxConcurrent: 1})

	release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := l.Acquire(ctx, "mb-1", Budget{MaxConcurrent: 1}); err == nil {
		t.Error("Acquire with a canceled context succeeded")
	}
}

func TestLimiterReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	l := NewLimiter(Budget{PerMinute: 30, MaxConcurrent: 1})

	release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()
	// A double release must not free a slot that was never taken, or the
	// concurrency cap would drift upwards over time.
	release()

	first, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	defer first()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "mb-1", Budget{MaxConcurrent: 1}); err == nil {
		t.Error("the concurrency cap drifted after a double release")
	}
}

func TestLimiterRebuildsOnABudgetChange(t *testing.T) {
	t.Parallel()

	l := NewLimiter(Budget{PerMinute: 30, MaxConcurrent: 1})

	release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	// Raising the limit in the admin interface must take effect without a
	// restart.
	second, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 3})
	if err != nil {
		t.Fatalf("Acquire after raising the budget: %v", err)
	}
	second()
}

func TestLimiterForget(t *testing.T) {
	t.Parallel()

	l := NewLimiter(Budget{PerMinute: 30, MaxConcurrent: 1})
	release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()

	l.Forget("mb-1")
	// Forgetting a deleted mailbox must not wedge later use of the same id.
	again, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 1})
	if err != nil {
		t.Fatalf("Acquire after Forget: %v", err)
	}
	again()
}

func TestLimiterIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	l := NewLimiter(Budget{PerMinute: ExchangeMessagesPerMinute, MaxConcurrent: 3})

	var (
		wg      sync.WaitGroup
		inUse   atomic.Int32
		maxSeen atomic.Int32
	)

	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			release, err := l.Acquire(t.Context(), "mb-1", Budget{MaxConcurrent: 3})
			if err != nil {
				return
			}
			defer release()

			n := inUse.Add(1)
			for {
				prev := maxSeen.Load()
				if n <= prev || maxSeen.CompareAndSwap(prev, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			inUse.Add(-1)
		}()
	}
	wg.Wait()

	// Exchange Online allows three concurrent submissions per mailbox; going
	// over produces errors rather than throughput.
	if got := maxSeen.Load(); got > 3 {
		t.Errorf("%d deliveries ran concurrently, want at most 3", got)
	}
}

func TestTokenBucketRefills(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := newTokenBucket(60, start)

	// Drain it.
	for range 60 {
		if _, ok := b.take(start); !ok {
			t.Fatal("the bucket ran dry before its capacity")
		}
	}
	wait, ok := b.take(start)
	if ok {
		t.Fatal("the bucket handed out a token it did not have")
	}
	if wait <= 0 || wait > time.Second {
		t.Errorf("wait = %v, want about one second at 60/minute", wait)
	}

	// One second later, one token is back.
	if _, ok := b.take(start.Add(time.Second)); !ok {
		t.Error("the bucket did not refill")
	}

	// After a long idle period it must not exceed its capacity.
	later := start.Add(time.Hour)
	for i := range 60 {
		if _, ok := b.take(later); !ok {
			t.Fatalf("the bucket refilled to only %d tokens", i)
		}
	}
	if _, ok := b.take(later); ok {
		t.Error("the bucket refilled past its capacity")
	}
}
