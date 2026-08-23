package queue

import (
	"testing"
	"time"
)

// fixed makes jitter deterministic.
func fixed(v float64) func() float64 { return func() float64 { return v } }

func TestBackoffFollowsTheSchedule(t *testing.T) {
	t.Parallel()

	b := Backoff{
		Delays:      []time.Duration{time.Minute, 5 * time.Minute, time.Hour},
		MaxAttempts: 10,
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{attempts: 1, want: time.Minute},
		{attempts: 2, want: 5 * time.Minute},
		{attempts: 3, want: time.Hour},
		// Past the end of the list the last delay repeats, rather than the
		// schedule wrapping back to a minute.
		{attempts: 4, want: time.Hour},
		{attempts: 9, want: time.Hour},
	}

	for _, tt := range tests {
		next, ok := b.NextAttempt(now, tt.attempts, now)
		if !ok {
			t.Fatalf("attempt %d: NextAttempt said not to retry", tt.attempts)
		}
		if got := next.Sub(now); got != tt.want {
			t.Errorf("attempt %d: delay = %v, want %v", tt.attempts, got, tt.want)
		}
	}
}

func TestBackoffStopsAtMaxAttempts(t *testing.T) {
	t.Parallel()

	b := Backoff{Delays: []time.Duration{time.Minute}, MaxAttempts: 3}
	now := time.Now()

	if _, ok := b.NextAttempt(now, 2, now); !ok {
		t.Error("gave up before reaching the attempt limit")
	}
	if _, ok := b.NextAttempt(now, 3, now); ok {
		t.Error("kept retrying at the attempt limit")
	}
	if _, ok := b.NextAttempt(now, 99, now); ok {
		t.Error("kept retrying past the attempt limit")
	}
}

func TestBackoffStopsAtMaxAge(t *testing.T) {
	t.Parallel()

	b := Backoff{
		Delays:      []time.Duration{time.Hour},
		MaxAttempts: 100,
		MaxAge:      3 * time.Hour,
	}
	received := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Well inside the window.
	if _, ok := b.NextAttempt(received.Add(time.Hour), 1, received); !ok {
		t.Error("gave up while still inside the maximum age")
	}
	// The next attempt would land past the deadline. Scheduling it would leave
	// the message looking alive when it is not.
	if _, ok := b.NextAttempt(received.Add(2*time.Hour+30*time.Minute), 1, received); ok {
		t.Error("scheduled an attempt beyond the maximum age")
	}
	// Already past it.
	if _, ok := b.NextAttempt(received.Add(4*time.Hour), 1, received); ok {
		t.Error("kept retrying past the maximum age")
	}
}

func TestBackoffIgnoresMaxAgeWithoutAReceivedTime(t *testing.T) {
	t.Parallel()

	b := Backoff{Delays: []time.Duration{time.Minute}, MaxAttempts: 5, MaxAge: time.Hour}
	if _, ok := b.NextAttempt(time.Now(), 1, time.Time{}); !ok {
		t.Error("a zero received time should not count as infinitely old")
	}
}

func TestBackoffJitterOnlyShortensTheDelay(t *testing.T) {
	t.Parallel()

	base := time.Hour
	now := time.Now()

	// Jitter must never push a retry past the configured maximum age, so it is
	// applied downwards only.
	full := Backoff{Delays: []time.Duration{base}, MaxAttempts: 5, Jitter: 0.2, random: fixed(1)}
	next, ok := full.NextAttempt(now, 1, now)
	if !ok {
		t.Fatal("NextAttempt said not to retry")
	}
	if got := next.Sub(now); got != base-time.Duration(0.2*float64(base)) {
		t.Errorf("with maximum jitter the delay = %v, want %v", got, base-12*time.Minute)
	}

	none := Backoff{Delays: []time.Duration{base}, MaxAttempts: 5, Jitter: 0.2, random: fixed(0)}
	next, _ = none.NextAttempt(now, 1, now)
	if got := next.Sub(now); got != base {
		t.Errorf("with no jitter the delay = %v, want %v", got, base)
	}
}

func TestBackoffJitterIsClamped(t *testing.T) {
	t.Parallel()

	now := time.Now()
	base := time.Hour

	// A misconfigured jitter must not produce a negative delay.
	b := Backoff{Delays: []time.Duration{base}, MaxAttempts: 5, Jitter: 5, random: fixed(1)}
	next, ok := b.NextAttempt(now, 1, now)
	if !ok {
		t.Fatal("NextAttempt said not to retry")
	}
	if next.Before(now) {
		t.Errorf("the retry time %v is in the past", next)
	}

	negative := Backoff{Delays: []time.Duration{base}, MaxAttempts: 5, Jitter: -1, random: fixed(1)}
	next, _ = negative.NextAttempt(now, 1, now)
	if got := next.Sub(now); got != base {
		t.Errorf("negative jitter changed the delay to %v", got)
	}
}

func TestBackoffFallsBackToTheDefaultSchedule(t *testing.T) {
	t.Parallel()

	b := Backoff{MaxAttempts: 20}
	now := time.Now()

	next, ok := b.NextAttempt(now, 1, now)
	if !ok {
		t.Fatal("NextAttempt said not to retry")
	}
	if got := next.Sub(now); got != DefaultDelays[0] {
		t.Errorf("delay = %v, want the first default of %v", got, DefaultDelays[0])
	}
}

func TestBackoffHandlesAZerothAttempt(t *testing.T) {
	t.Parallel()

	b := Backoff{Delays: []time.Duration{time.Minute, time.Hour}, MaxAttempts: 5}
	now := time.Now()

	// Defensive: a caller passing 0 must get the first delay, not an index
	// out of range.
	next, ok := b.NextAttempt(now, 0, now)
	if !ok {
		t.Fatal("NextAttempt said not to retry")
	}
	if got := next.Sub(now); got != time.Minute {
		t.Errorf("delay = %v, want the first entry", got)
	}
}

func TestNextAttemptAfterHonorsAnUpstreamDelay(t *testing.T) {
	t.Parallel()

	b := Backoff{Delays: []time.Duration{time.Minute}, MaxAttempts: 10}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// The upstream asked for longer than the schedule: never retry sooner than
	// we were told to.
	next, ok := b.NextAttemptAfter(now, 1, now, 10*time.Minute)
	if !ok {
		t.Fatal("NextAttemptAfter said not to retry")
	}
	if got := next.Sub(now); got != 10*time.Minute {
		t.Errorf("delay = %v, want the upstream's 10m", got)
	}

	// The upstream asked for less: the schedule wins, so a server that says
	// "one second" cannot make the proxy hammer it.
	next, _ = b.NextAttemptAfter(now, 1, now, time.Second)
	if got := next.Sub(now); got != time.Minute {
		t.Errorf("delay = %v, want the scheduled 1m", got)
	}

	// No delay named.
	next, _ = b.NextAttemptAfter(now, 1, now, 0)
	if got := next.Sub(now); got != time.Minute {
		t.Errorf("delay = %v, want the scheduled 1m", got)
	}

	// A retry the schedule has already given up on stays given up on.
	if _, ok := b.NextAttemptAfter(now, 10, now, time.Minute); ok {
		t.Error("an upstream delay revived a message past its attempt limit")
	}
}

func TestClampJitter(t *testing.T) {
	t.Parallel()

	tests := map[float64]float64{
		-1:  0,
		0:   0,
		0.2: 0.2,
		1:   1,
		5:   1,
	}
	for in, want := range tests {
		if got := clampJitter(in); got != want {
			t.Errorf("clampJitter(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestBackoffUsesRealRandomnessByDefault(t *testing.T) {
	t.Parallel()

	// Without an injected source the jitter must still stay inside its bounds,
	// and must actually vary — a constant would defeat the point of spreading
	// a batch of retries.
	b := Backoff{Delays: []time.Duration{time.Hour}, MaxAttempts: 5, Jitter: 0.5}
	now := time.Now()

	seen := make(map[time.Duration]struct{}, 32)
	for range 32 {
		next, ok := b.NextAttempt(now, 1, now)
		if !ok {
			t.Fatal("NextAttempt said not to retry")
		}
		delay := next.Sub(now)
		if delay < 30*time.Minute || delay > time.Hour {
			t.Fatalf("delay %v is outside the jittered range of 30m..1h", delay)
		}
		seen[delay] = struct{}{}
	}
	if len(seen) < 2 {
		t.Error("the jitter produced the same delay every time")
	}
}
