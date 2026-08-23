// Package queue delivers spooled messages to Microsoft 365.
//
// Delivery is deliberately paced. Exchange Online allows a mailbox 30 messages
// per minute and 3 concurrent submissions, and exceeding either produces
// "4.7.500 Server busy" rather than a queued message. The workers therefore
// enforce their own budget below those limits instead of discovering them.
package queue

import (
	"math/rand/v2"
	"time"
)

// Backoff schedules retries.
type Backoff struct {
	// Delays are used in order; the last entry repeats once the list runs out.
	Delays []time.Duration
	// Jitter spreads retries as a fraction of the delay, between 0 and 1. A
	// batch of messages queued together would otherwise all retry at the same
	// instant and hit the rate limit as a group.
	Jitter float64
	// MaxAttempts gives up after this many tries.
	MaxAttempts int
	// MaxAge gives up this long after the message was accepted, whichever comes
	// first. A message that has been retrying for days is not going to succeed,
	// and holding it forever hides the failure.
	MaxAge time.Duration

	// random is injectable so tests get deterministic jitter.
	random func() float64
}

// DefaultDelays matches the configuration defaults: quick first, then patient.
var DefaultDelays = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute,
	time.Hour, 4 * time.Hour, 12 * time.Hour,
}

// NextAttempt returns when a message should be retried, and whether it should
// be retried at all.
//
// attempts is the number of attempts already made, including the one that just
// failed. receivedAt is when the message was accepted.
func (b Backoff) NextAttempt(now time.Time, attempts int, receivedAt time.Time) (time.Time, bool) {
	if b.MaxAttempts > 0 && attempts >= b.MaxAttempts {
		return time.Time{}, false
	}

	delay := b.delayFor(attempts)
	next := now.Add(delay)

	// Giving up at MaxAge is checked against the retry time, not the current
	// one: scheduling an attempt that would happen after the deadline is the
	// same as not retrying, and leaves the message looking alive when it is not.
	if b.MaxAge > 0 && !receivedAt.IsZero() && next.After(receivedAt.Add(b.MaxAge)) {
		return time.Time{}, false
	}
	return next, true
}

// delayFor returns the base delay for the next attempt, with jitter applied.
func (b Backoff) delayFor(attempts int) time.Duration {
	delays := b.Delays
	if len(delays) == 0 {
		delays = DefaultDelays
	}

	// attempts is 1 after the first failure, which should use the first delay.
	index := attempts - 1
	if index < 0 {
		index = 0
	}
	if index >= len(delays) {
		index = len(delays) - 1
	}
	delay := delays[index]

	if b.Jitter <= 0 {
		return delay
	}

	// Jitter is applied downwards only, so a configured maximum age still means
	// what it says.
	spread := float64(delay) * clampJitter(b.Jitter)
	return delay - time.Duration(spread*b.randomValue())
}

func (b Backoff) randomValue() float64 {
	if b.random != nil {
		return b.random()
	}
	return rand.Float64() //nolint:gosec // scheduling jitter, not a security decision
}

func clampJitter(j float64) float64 {
	switch {
	case j < 0:
		return 0
	case j > 1:
		return 1
	default:
		return j
	}
}

// NextAttemptAfter honors a delay the upstream explicitly asked for, such as
// Graph's Retry-After header, taking whichever is later so the proxy never
// retries sooner than it was told to.
func (b Backoff) NextAttemptAfter(now time.Time, attempts int, receivedAt time.Time, requested time.Duration) (time.Time, bool) {
	next, ok := b.NextAttempt(now, attempts, receivedAt)
	if !ok {
		return time.Time{}, false
	}
	if requested > 0 {
		if asked := now.Add(requested); asked.After(next) {
			next = asked
		}
	}
	return next, true
}
