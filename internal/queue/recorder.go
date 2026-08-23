package queue

import "time"

// Recorder receives what happened, for metrics.
//
// An interface rather than a direct dependency on the metrics package, so this
// package stays testable without a registry.
type Recorder interface {
	// Delivery records one upstream attempt.
	Delivery(transport, result string, took time.Duration)
	// QueueDepth reports how many messages sit in each status.
	QueueDepth(status string, count float64)
	// CredentialExpiry reports how long a credential has left.
	CredentialExpiry(name string, seconds float64)
}

// Delivery outcomes.
const (
	DeliverySent = "sent"
	// DeliveryDeferred will be retried.
	DeliveryDeferred = "deferred"
	// DeliveryFailed will not.
	DeliveryFailed = "failed"
)

type nopRecorder struct{}

func (nopRecorder) Delivery(string, string, time.Duration) {}
func (nopRecorder) QueueDepth(string, float64)             {}
func (nopRecorder) CredentialExpiry(string, float64)       {}
