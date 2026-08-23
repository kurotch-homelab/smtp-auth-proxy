package metrics_test

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/metrics"
)

func TestCollectorsAreRegistered(t *testing.T) {
	t.Parallel()

	m := metrics.New()

	// Give every series a value so it appears in a gather.
	m.SubmissionsTotal.WithLabelValues("accepted").Inc()
	m.AuthFailuresTotal.WithLabelValues("bad_password").Inc()
	m.DeliveriesTotal.WithLabelValues("smtp", "sent").Inc()
	m.DeliveryDuration.WithLabelValues("smtp").Observe(0.42)
	m.QueueDepth.WithLabelValues("queued").Set(3)
	m.CredentialExpirySeconds.WithLabelValues("primary").Set(86400)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}

	// These are what an operator alerts on; renaming one silently breaks every
	// dashboard built against it.
	want := []string{
		"smtp_auth_proxy_submissions_total",
		"smtp_auth_proxy_smtp_auth_failures_total",
		"smtp_auth_proxy_deliveries_total",
		"smtp_auth_proxy_delivery_duration_seconds",
		"smtp_auth_proxy_queue_depth",
		"smtp_auth_proxy_credential_expiry_seconds",
	}
	for _, name := range want {
		if !names[name] {
			t.Errorf("the registry has no %s", name)
		}
	}
}

func TestRuntimeCollectorsAreIncluded(t *testing.T) {
	t.Parallel()

	// Process and Go metrics are the first thing anyone asks for when a
	// container misbehaves.
	families, err := metrics.New().Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	var hasGo bool
	for _, f := range families {
		if strings.HasPrefix(f.GetName(), "go_") {
			hasGo = true
		}
	}
	if !hasGo {
		t.Error("the registry publishes no Go runtime metrics")
	}
}

func TestQueueDepthIsAGauge(t *testing.T) {
	t.Parallel()

	m := metrics.New()

	// A gauge, not a counter: the queue shrinks as it drains, and a counter
	// would make "is the queue growing" unanswerable.
	m.QueueDepth.WithLabelValues("queued").Set(5)
	m.QueueDepth.WithLabelValues("queued").Set(2)

	if got := testutil.ToFloat64(m.QueueDepth.WithLabelValues("queued")); got != 2 {
		t.Errorf("queue depth = %v, want the latest value", got)
	}
}

// An alerting rule like rate(...[5m]) > 0 evaluates to nothing against an
// absent series, so a freshly started proxy would have no alerting until its
// first failure — exactly when it is needed.
func TestInitPublishesEverySeriesAtZero(t *testing.T) {
	t.Parallel()

	m := metrics.New()
	m.Init([]string{"smtp", "graph"})

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	series := map[string]int{}
	for _, f := range families {
		series[f.GetName()] = len(f.GetMetric())
	}

	if series["smtp_auth_proxy_submissions_total"] != 3 {
		t.Errorf("submissions has %d series, want one per outcome",
			series["smtp_auth_proxy_submissions_total"])
	}
	if series["smtp_auth_proxy_smtp_auth_failures_total"] != 2 {
		t.Errorf("auth failures has %d series, want one per reason",
			series["smtp_auth_proxy_smtp_auth_failures_total"])
	}
	// Two transports times three outcomes.
	if series["smtp_auth_proxy_deliveries_total"] != 6 {
		t.Errorf("deliveries has %d series, want 6", series["smtp_auth_proxy_deliveries_total"])
	}

	if got := testutil.ToFloat64(m.SubmissionsTotal.WithLabelValues("accepted")); got != 0 {
		t.Errorf("a pre-created counter starts at %v, want 0", got)
	}
}
