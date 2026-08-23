package smtpsrv

// Recorder receives what happened, for metrics.
//
// It is an interface rather than a direct dependency on the metrics package so
// this package stays testable without a metrics registry, and so a deployment
// that turns metrics off pays nothing.
type Recorder interface {
	// Submission records one message accepted or refused.
	Submission(result string)
	// AuthFailure records one refused sign-in.
	AuthFailure(reason string)
}

// Submission outcomes.
const (
	SubmissionAccepted = "accepted"
	// SubmissionRejected is a message refused by the sender policy or by
	// validation — the client's problem.
	SubmissionRejected = "rejected"
	// SubmissionFailed is a message the proxy could not queue — our problem.
	SubmissionFailed = "failed"
)

// Authentication failure reasons. These are coarse on purpose: a per-username
// label would let anyone who can submit mail create unbounded time series.
const (
	AuthFailureCredentials = "credentials"
	AuthFailureNoTLS       = "encryption_required"
)

// nopRecorder is used when no recorder was supplied.
type nopRecorder struct{}

func (nopRecorder) Submission(string)  {}
func (nopRecorder) AuthFailure(string) {}
