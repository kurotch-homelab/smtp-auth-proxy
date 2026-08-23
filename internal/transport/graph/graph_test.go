package graph_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport/graph"
)

const graphScope = "https://graph.microsoft.com/.default"

// fakeTokens hands out a fixed token.
type fakeTokens struct {
	token string
	err   error
}

func (f *fakeTokens) Token(context.Context, *store.OAuthCredential, string) (oauth.Token, error) {
	if f.err != nil {
		return oauth.Token{}, f.err
	}
	return oauth.Token{AccessToken: f.token, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// request captures what the fake Graph endpoint received.
type request struct {
	Method      string
	Path        string
	Auth        string
	ContentType string
	Body        string
	RequestID   string
}

// fakeGraph is a stand-in for the sendMail endpoint.
type fakeGraph struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []request
	// status and body replace the 202 when set.
	status     int
	body       string
	retryAfter string
}

func startFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()

	f := &fakeGraph{status: http.StatusAccepted}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		f.mu.Lock()
		f.requests = append(f.requests, request{
			Method:      r.Method,
			Path:        r.URL.Path,
			Auth:        r.Header.Get("Authorization"),
			ContentType: r.Header.Get("Content-Type"),
			Body:        string(body),
			RequestID:   r.Header.Get("client-request-id"),
		})
		status, respBody, retry := f.status, f.body, f.retryAfter
		f.mu.Unlock()

		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.Header().Set("request-id", "fake-request-id")
		w.WriteHeader(status)
		if respBody != "" {
			_, _ = w.Write([]byte(respBody))
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGraph) respond(status int, body, retryAfter string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body, f.retryAfter = status, body, retryAfter
}

func (f *fakeGraph) seen() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.requests...)
}

func setup(t *testing.T, tokens *fakeTokens) (*fakeGraph, *graph.Transport) {
	t.Helper()

	fake := startFakeGraph(t)
	tr, err := graph.New(graph.Options{
		Endpoint:   fake.server.URL,
		Scope:      graphScope,
		Timeout:    10 * time.Second,
		HTTPClient: fake.server.Client(),
		Tokens:     tokens,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("graph.New: %v", err)
	}
	return fake, tr
}

func testMessage() *transport.Message {
	return &transport.Message{
		ID:         "msg-1",
		Mailbox:    &store.Mailbox{ID: "mb-1", Address: "shared@example.com", Enabled: true},
		Credential: &store.OAuthCredential{ID: "cred-1", Name: "primary"},
		Recipients: []string{"ops@example.net"},
		Raw:        []byte("From: shared@example.com\r\nTo: ops@example.net\r\nSubject: hi\r\n\r\nbody\r\n"),
	}
}

func TestSendPostsMIMEToTheMailbox(t *testing.T) {
	t.Parallel()

	fake, tr := setup(t, &fakeTokens{token: "T0K3N"})

	if err := tr.Send(t.Context(), testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	seen := fake.seen()
	if len(seen) != 1 {
		t.Fatalf("the endpoint saw %d requests, want 1", len(seen))
	}
	r := seen[0]

	if r.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", r.Method)
	}
	// The mailbox selects the sending identity, exactly as the XOAUTH2 user
	// field does for SMTP.
	if r.Path != "/v1.0/users/shared@example.com/sendMail" {
		t.Errorf("path = %q", r.Path)
	}
	// text/plain is what tells Graph the body is MIME rather than JSON; sending
	// application/json would make it reject a perfectly good message.
	if r.ContentType != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", r.ContentType)
	}
	if r.Auth != "Bearer T0K3N" {
		t.Errorf("Authorization = %q", r.Auth)
	}
	if r.RequestID != "msg-1" {
		t.Errorf("client-request-id = %q, want the queue id so a delivery is traceable", r.RequestID)
	}

	// Graph expects standard base64 with padding.
	decoded, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		t.Fatalf("the body is not standard base64: %v", err)
	}
	if !strings.Contains(string(decoded), "Subject: hi") {
		t.Errorf("the message did not survive encoding:\n%s", decoded)
	}
}

func TestSendEscapesTheMailboxInThePath(t *testing.T) {
	t.Parallel()

	fake, tr := setup(t, &fakeTokens{token: "T0K3N"})
	m := testMessage()
	// A plus-addressed mailbox has to survive path encoding rather than being
	// read as a space.
	m.Mailbox.Address = "shared+alias@example.com"

	if err := tr.Send(t.Context(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := fake.seen()[0].Path; got != "/v1.0/users/shared+alias@example.com/sendMail" {
		t.Errorf("path = %q", got)
	}
}

func TestSendClassifiesResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		status        int
		body          string
		retryAfter    string
		wantPermanent bool
		wantAuth      bool
		wantCode      string
		wantRetry     time.Duration
	}{
		{
			name:   "202 is success",
			status: http.StatusAccepted,
		},
		{
			// The tenant is throttling; the delay it names must be honored, or
			// the proxy just gets throttled harder.
			name:       "429 is retried after the delay Graph names",
			status:     http.StatusTooManyRequests,
			body:       `{"error":{"code":"ApplicationThrottled","message":"Too many requests"}}`,
			retryAfter: "120",
			wantCode:   "ApplicationThrottled",
			wantRetry:  2 * time.Minute,
		},
		{
			// Mail.Send is missing, or an application access policy excludes
			// this mailbox. Retried, because it is a tenant setting.
			name:     "403 is an authentication failure",
			status:   http.StatusForbidden,
			body:     `{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`,
			wantCode: "ErrorAccessDenied",
			wantAuth: true,
		},
		{
			name:     "401 is an authentication failure",
			status:   http.StatusUnauthorized,
			body:     `{"error":{"code":"InvalidAuthenticationToken","message":"Access token is empty."}}`,
			wantCode: "InvalidAuthenticationToken",
			wantAuth: true,
		},
		{
			name:          "404 means the mailbox does not exist",
			status:        http.StatusNotFound,
			body:          `{"error":{"code":"ErrorInvalidUser","message":"The requested user is invalid."}}`,
			wantCode:      "ErrorInvalidUser",
			wantPermanent: true,
		},
		{
			name:          "400 is permanent",
			status:        http.StatusBadRequest,
			body:          `{"error":{"code":"ErrorMimeContentInvalidBase64String","message":"Invalid base64 string for MIME content."}}`,
			wantCode:      "ErrorMimeContentInvalidBase64String",
			wantPermanent: true,
		},
		{
			name:     "503 is retried",
			status:   http.StatusServiceUnavailable,
			body:     `{"error":{"code":"ServiceUnavailable","message":"Try again later."}}`,
			wantCode: "ServiceUnavailable",
		},
		{
			// A proxy in between may return HTML rather than Graph's envelope;
			// the operator still needs to see it.
			name:     "a non-JSON error body is preserved",
			status:   http.StatusBadGateway,
			body:     "<html><body>502 Bad Gateway</body></html>",
			wantCode: "502",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fake, tr := setup(t, &fakeTokens{token: "T0K3N"})
			fake.respond(tt.status, tt.body, tt.retryAfter)

			err := tr.Send(t.Context(), testMessage())
			if tt.status == http.StatusAccepted {
				if err != nil {
					t.Fatalf("Send = %v, want nil for 202", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Send = nil, want an error for %d", tt.status)
			}

			var terr *transport.Error
			if !errors.As(err, &terr) {
				t.Fatalf("Send returned %T, want *transport.Error", err)
			}
			if terr.Permanent != tt.wantPermanent {
				t.Errorf("Permanent = %v, want %v (%v)", terr.Permanent, tt.wantPermanent, err)
			}
			if transport.IsAuthFailure(err) != tt.wantAuth {
				t.Errorf("IsAuthFailure = %v, want %v", transport.IsAuthFailure(err), tt.wantAuth)
			}
			if tt.wantCode != "" && terr.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", terr.Code, tt.wantCode)
			}
			if tt.wantRetry != 0 && transport.RetryAfter(err) != tt.wantRetry {
				t.Errorf("RetryAfter = %v, want %v", transport.RetryAfter(err), tt.wantRetry)
			}
			if tt.status == http.StatusBadGateway && !strings.Contains(terr.Message, "Bad Gateway") {
				t.Errorf("the non-JSON body was lost: %q", terr.Message)
			}
		})
	}
}

func TestRetryAfterAcceptsAnHTTPDate(t *testing.T) {
	t.Parallel()

	fake, tr := setup(t, &fakeTokens{token: "T0K3N"})
	when := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	fake.respond(http.StatusTooManyRequests, `{"error":{"code":"Throttled","message":"slow down"}}`, when)

	err := tr.Send(t.Context(), testMessage())
	if err == nil {
		t.Fatal("Send succeeded despite a 429")
	}
	got := transport.RetryAfter(err)
	if got < 60*time.Second || got > 100*time.Second {
		t.Errorf("RetryAfter = %v, want roughly 90s from an HTTP date", got)
	}
}

// Graph's sendMail takes MIME up to 4 MB. There is no larger path that does not
// mean rebuilding the message, so the limit is reported clearly instead.
func TestOversizedMessageIsRejectedWithGuidance(t *testing.T) {
	t.Parallel()

	fake, tr := setup(t, &fakeTokens{token: "T0K3N"})

	m := testMessage()
	m.Raw = make([]byte, graph.MaxMIMESize+1)

	err := tr.Send(t.Context(), m)
	if err == nil {
		t.Fatal("Send accepted a message over the size limit")
	}
	if !transport.IsPermanent(err) {
		t.Error("an oversized message should not be retried; it will never fit")
	}
	if !strings.Contains(err.Error(), "SMTP transport") {
		t.Errorf("the error does not say what to do instead: %v", err)
	}
	// Nothing should have been sent, and no token spent.
	if n := len(fake.seen()); n != 0 {
		t.Errorf("%d requests were made for an oversized message", n)
	}
}

func TestTokenFailureIsRetried(t *testing.T) {
	t.Parallel()

	_, tr := setup(t, &fakeTokens{err: errors.New("the secret expired")})

	err := tr.Send(t.Context(), testMessage())
	if err == nil {
		t.Fatal("Send succeeded without a token")
	}
	if transport.IsPermanent(err) {
		t.Errorf("a token failure was treated as permanent: %v", err)
	}
}

func TestUnreachableEndpointIsRetried(t *testing.T) {
	t.Parallel()

	tr, err := graph.New(graph.Options{
		// Port 1 on the loopback interface refuses connections.
		Endpoint: "http://127.0.0.1:1",
		Scope:    graphScope,
		Timeout:  2 * time.Second,
		Tokens:   &fakeTokens{token: "T0K3N"},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("graph.New: %v", err)
	}

	sendErr := tr.Send(t.Context(), testMessage())
	if sendErr == nil {
		t.Fatal("Send succeeded against a closed port")
	}
	if transport.IsPermanent(sendErr) {
		t.Errorf("an unreachable endpoint was treated as permanent: %v", sendErr)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()

	tests := map[string]graph.Options{
		"no token source": {Endpoint: "https://graph.microsoft.com", Scope: graphScope},
		"no endpoint":     {Scope: graphScope, Tokens: &fakeTokens{}},
		"no scope":        {Endpoint: "https://graph.microsoft.com", Tokens: &fakeTokens{}},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := graph.New(opts); err == nil {
				t.Error("New accepted invalid options")
			}
		})
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	_, tr := setup(t, &fakeTokens{token: "T0K3N"})
	if got := tr.Name(); got != "graph" {
		t.Errorf("Name() = %q, want graph", got)
	}
}
