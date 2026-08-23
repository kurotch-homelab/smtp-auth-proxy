package adminapi

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsHandler serves the Prometheus endpoint.
//
// It is deliberately unauthenticated. A scrape has no session, and the metrics
// carry counts and durations rather than addresses or message contents — but a
// deployment that would rather not expose even that can turn it off, or keep
// the admin port off the network its scraper cannot reach.
func (s *Server) metricsHandler() http.Handler {
	if s.metrics == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics are not enabled", http.StatusNotFound)
		})
	}
	return promhttp.HandlerFor(s.metrics.Registry(), promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
}
