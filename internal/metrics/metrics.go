// Package metrics exposes what an operator needs to alert on: whether mail is
// getting through, and whether the queue is growing.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds every collector the proxy publishes.
type Metrics struct {
	registry *prometheus.Registry

	// SubmissionsTotal counts messages accepted from LAN clients, by outcome.
	SubmissionsTotal *prometheus.CounterVec
	// AuthFailuresTotal counts refused SMTP sign-ins, which is what a
	// misconfigured device or a guessing attack looks like.
	AuthFailuresTotal *prometheus.CounterVec
	// DeliveriesTotal counts upstream attempts, by transport and outcome.
	DeliveriesTotal *prometheus.CounterVec
	// DeliveryDuration measures how long an upstream attempt takes.
	DeliveryDuration *prometheus.HistogramVec
	// QueueDepth reports how many messages sit in each state. This is the
	// number worth alerting on: a queue that stops draining means mail is not
	// being delivered, whatever the error counters say.
	QueueDepth *prometheus.GaugeVec
	// CredentialExpirySeconds reports how long each credential has left, so an
	// expiry can be caught before it takes mail down.
	CredentialExpirySeconds *prometheus.GaugeVec
}

// New builds the collectors and registers them.
func New() *Metrics {
	registry := prometheus.NewRegistry()

	m := &Metrics{
		registry: registry,
		SubmissionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "smtp_auth_proxy",
			Name:      "submissions_total",
			Help:      "Messages accepted from LAN clients, by outcome.",
		}, []string{"result"}),
		AuthFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "smtp_auth_proxy",
			Name:      "smtp_auth_failures_total",
			Help:      "Refused SMTP authentication attempts, by reason.",
		}, []string{"reason"}),
		DeliveriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "smtp_auth_proxy",
			Name:      "deliveries_total",
			Help:      "Upstream delivery attempts, by transport and outcome.",
		}, []string{"transport", "result"}),
		DeliveryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "smtp_auth_proxy",
			Name:      "delivery_duration_seconds",
			Help:      "How long an upstream delivery attempt takes.",
			// Exchange Online is usually sub-second but occasionally takes tens
			// of seconds under throttling, so the buckets span both.
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120},
		}, []string{"transport"}),
		QueueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "smtp_auth_proxy",
			Name:      "queue_depth",
			Help:      "Messages in the queue, by status.",
		}, []string{"status"}),
		CredentialExpirySeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "smtp_auth_proxy",
			Name:      "credential_expiry_seconds",
			Help:      "Seconds until an OAuth credential expires; negative once it has.",
		}, []string{"credential"}),
	}

	registry.MustRegister(
		m.SubmissionsTotal,
		m.AuthFailuresTotal,
		m.DeliveriesTotal,
		m.DeliveryDuration,
		m.QueueDepth,
		m.CredentialExpirySeconds,
		// Process and Go runtime metrics come for free and are the first thing
		// anyone asks for when a container misbehaves.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)

	return m
}

// Registry exposes the registry, for the HTTP handler.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Init creates the series for every label combination the proxy knows about,
// at zero.
//
// A counter that has never been incremented is simply absent, and an alerting
// rule like rate(...[5m]) > 0 evaluates to nothing at all against an absent
// series — so a freshly started proxy would have no alerting until its first
// failure, which is exactly when the alert is needed.
func (m *Metrics) Init(transports []string) {
	for _, result := range []string{"accepted", "rejected", "failed"} {
		m.SubmissionsTotal.WithLabelValues(result)
	}
	for _, reason := range []string{"credentials", "encryption_required"} {
		m.AuthFailuresTotal.WithLabelValues(reason)
	}
	for _, transport := range transports {
		for _, result := range []string{"sent", "deferred", "failed"} {
			m.DeliveriesTotal.WithLabelValues(transport, result)
		}
		m.DeliveryDuration.WithLabelValues(transport)
	}
}
