// Package graph delivers messages through the Microsoft Graph sendMail API.
//
// It is an alternative to relaying over SMTP. Graph is not subject to the SMTP
// client submission limits (30 messages a minute, 3 concurrent connections),
// and it lets a tenant disable SMTP AUTH entirely. In exchange it needs a
// different permission — Mail.Send rather than SMTP.SendAsApp — always saves a
// copy to Sent Items, and caps a MIME message at 4 MB.
package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/version"
)

// MaxMIMESize is the largest message the sendMail endpoint accepts in MIME
// form.
//
// There is deliberately no fallback for larger messages. Graph's upload-session
// flow attaches files to a JSON draft, so using it would mean parsing the MIME
// message apart and rebuilding it — which changes transfer encodings, re-folds
// headers and invalidates any signature the sender applied. A message that does
// not fit is rejected with an explanation instead, and the mailbox can be
// switched to the SMTP transport, which has no such limit.
const MaxMIMESize = 4 << 20

// Options configure the Graph transport.
type Options struct {
	// Endpoint is the Graph base URL, e.g. https://graph.microsoft.com.
	Endpoint string
	// Scope is the OAuth scope; https://graph.microsoft.com/.default.
	Scope string
	// Timeout bounds one delivery.
	Timeout time.Duration
	// HTTPClient is used for the request; nil builds a default.
	HTTPClient *http.Client
	// Tokens supplies access tokens.
	Tokens oauth.TokenSource
	Log    *slog.Logger
}

// Transport is a transport.Transport backed by Graph.
type Transport struct {
	opts Options
}

// New returns a Graph transport.
func New(opts Options) (*Transport, error) {
	if opts.Tokens == nil {
		return nil, errors.New("graph: a token source is required")
	}
	if opts.Endpoint == "" {
		return nil, errors.New("graph: an endpoint is required")
	}
	if opts.Scope == "" {
		return nil, errors.New("graph: an OAuth scope is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Minute
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: opts.Timeout}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Transport{opts: opts}, nil
}

// Name identifies this backend.
func (t *Transport) Name() string { return "graph" }

// Send delivers one message.
func (t *Transport) Send(ctx context.Context, m *transport.Message) error {
	if len(m.Raw) > MaxMIMESize {
		return transport.NewPermanent("graph.size", fmt.Sprintf(
			"the message is %d bytes, over the %d byte limit the Graph sendMail API accepts in MIME form; "+
				"switch this mailbox to the SMTP transport to send messages this large",
			len(m.Raw), MaxMIMESize), nil)
	}

	ctx, cancel := context.WithTimeout(ctx, t.opts.Timeout)
	defer cancel()

	token, err := t.opts.Tokens.Token(ctx, m.Credential, t.opts.Scope)
	if err != nil {
		return transport.NewTransient("oauth", "could not obtain an access token: "+err.Error(), err)
	}

	req, err := t.buildRequest(ctx, m, token.AccessToken)
	if err != nil {
		return err
	}

	resp, err := t.opts.HTTPClient.Do(req)
	if err != nil {
		return transport.NewTransient("net", "the Graph request failed: "+err.Error(), err)
	}
	defer func() {
		// Draining lets the connection be reused; the body is small.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	return t.classify(resp, m)
}

func (t *Transport) buildRequest(ctx context.Context, m *transport.Message, accessToken string) (*http.Request, error) {
	// The mailbox goes in the path, exactly as it does in the XOAUTH2 "user="
	// field for SMTP: it is what selects which mailbox the message is sent as.
	endpoint := strings.TrimRight(t.opts.Endpoint, "/") +
		"/v1.0/users/" + url.PathEscape(m.Mailbox.Address) + "/sendMail"

	// Graph wants the MIME message base64-encoded, with the standard alphabet
	// and padding.
	encoded := base64.StdEncoding.EncodeToString(m.Raw)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte(encoded)))
	if err != nil {
		return nil, transport.NewPermanent("graph", "could not build the Graph request: "+err.Error(), err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	// text/plain is what tells Graph the body is MIME rather than JSON.
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("User-Agent", version.UserAgent())
	// A client request id makes a delivery traceable in the tenant's own logs.
	req.Header.Set("client-request-id", m.ID)

	return req, nil
}

// classify turns a Graph response into success or a transport.Error.
func (t *Transport) classify(resp *http.Response, m *transport.Message) error {
	// 202 Accepted means Graph took the message. It does not mean it was
	// delivered — Exchange still applies its own limits downstream — but it is
	// the only acknowledgement this API offers.
	if resp.StatusCode == http.StatusAccepted {
		t.opts.Log.Debug("graph accepted a message",
			"message_id", m.ID, "mailbox", m.Mailbox.Address,
			"request_id", resp.Header.Get("request-id"))
		return nil
	}

	detail := readError(resp)
	code := detail.code(resp.StatusCode)
	message := detail.message(resp.StatusCode)

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// Graph names how long to wait; honoring it is what keeps a throttled
		// tenant from being throttled harder.
		return transport.NewThrottled(code, message, retryAfter(resp), nil)

	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return transport.NewAuthFailure(code, fmt.Sprintf(
			"sending as %s was refused: %s", m.Mailbox.Address, message), nil)

	case resp.StatusCode >= 500:
		return transport.NewTransient(code, message, nil)

	case resp.StatusCode == http.StatusNotFound:
		// The mailbox does not exist, or the application cannot see it.
		return transport.NewPermanent(code, fmt.Sprintf(
			"the mailbox %s was not found: %s", m.Mailbox.Address, message), nil)

	default:
		return transport.NewPermanent(code, message, nil)
	}
}

// graphError is the error envelope Graph returns.
type graphError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (g *graphError) code(status int) string {
	if g != nil && g.Error.Code != "" {
		return g.Error.Code
	}
	return strconv.Itoa(status)
}

func (g *graphError) message(status int) string {
	if g != nil && g.Error.Message != "" {
		return g.Error.Message
	}
	return http.StatusText(status)
}

// readError decodes the error body, tolerating a response that is not JSON.
func readError(resp *http.Response) *graphError {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || len(body) == 0 {
		return nil
	}

	var g graphError
	if err := json.Unmarshal(body, &g); err != nil || g.Error.Code == "" {
		// Not the envelope we expected. Keep the text, truncated: an HTML error
		// page from a proxy in between is still worth showing an operator.
		return &graphError{Error: struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{Message: truncate(strings.TrimSpace(string(body)), 512)}}
	}
	return &g
}

// retryAfter reads the Retry-After header, which Graph gives in seconds.
func retryAfter(resp *http.Response) time.Duration {
	raw := resp.Header.Get("Retry-After")
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	// The header may also be an HTTP date.
	if when, err := http.ParseTime(raw); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
