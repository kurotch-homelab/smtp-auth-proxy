package app

import (
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/metrics"
)

// recorder adapts the metrics collectors to the narrow interfaces the SMTP and
// queue packages ask for, so neither of them depends on Prometheus.
type recorder struct{ m *metrics.Metrics }

func (r recorder) Submission(result string) {
	r.m.SubmissionsTotal.WithLabelValues(result).Inc()
}

func (r recorder) AuthFailure(reason string) {
	r.m.AuthFailuresTotal.WithLabelValues(reason).Inc()
}

func (r recorder) Delivery(transport, result string, took time.Duration) {
	r.m.DeliveriesTotal.WithLabelValues(transport, result).Inc()
	r.m.DeliveryDuration.WithLabelValues(transport).Observe(took.Seconds())
}

func (r recorder) QueueDepth(status string, count float64) {
	r.m.QueueDepth.WithLabelValues(status).Set(count)
}

func (r recorder) CredentialExpiry(name string, seconds float64) {
	r.m.CredentialExpirySeconds.WithLabelValues(name).Set(seconds)
}
