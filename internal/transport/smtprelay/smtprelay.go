// Package smtprelay delivers messages to Exchange Online over SMTP, using SASL
// XOAUTH2 to authenticate.
//
// This is the transport that keeps the semantics a LAN service already expects:
// the enhanced status codes and rejection reasons Exchange returns are the ones
// recorded in the queue, rather than a translation of them.
package smtprelay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/oauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/transport"
)

// Options configure the relay.
type Options struct {
	// Host and Port address Exchange Online; smtp.office365.com:587.
	Host string
	Port int
	// Scope is the OAuth scope the access token is requested for. Exchange
	// Online requires https://outlook.office365.com/.default for SMTP AUTH.
	Scope string
	// LocalName is sent in EHLO.
	LocalName string
	// Timeout bounds one whole delivery.
	Timeout time.Duration
	// TLSConfig overrides the client TLS settings; nil uses secure defaults.
	TLSConfig *tls.Config
	// Tokens supplies access tokens.
	Tokens oauth.TokenSource
	// Dial overrides how the connection is made, for tests.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	Log  *slog.Logger
}

// Relay is a transport.Transport backed by SMTP.
type Relay struct {
	opts Options
}

// New returns a relay.
func New(opts Options) (*Relay, error) {
	if opts.Tokens == nil {
		return nil, errors.New("smtprelay: a token source is required")
	}
	if opts.Host == "" {
		return nil, errors.New("smtprelay: an upstream host is required")
	}
	if opts.Port == 0 {
		opts.Port = 587
	}
	if opts.Scope == "" {
		return nil, errors.New("smtprelay: an OAuth scope is required")
	}
	if opts.LocalName == "" {
		opts.LocalName = "localhost"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Minute
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Dial == nil {
		var d net.Dialer
		opts.Dial = d.DialContext
	}
	return &Relay{opts: opts}, nil
}

// Name identifies this backend.
func (r *Relay) Name() string { return "smtp" }

// Send delivers one message.
func (r *Relay) Send(ctx context.Context, m *transport.Message) error {
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	token, err := r.opts.Tokens.Token(ctx, m.Credential, r.opts.Scope)
	if err != nil {
		// No token means no delivery, but the credential is usually fixable,
		// so this is worth retrying rather than failing the message.
		return transport.NewTransient("oauth", "could not obtain an access token: "+err.Error(), err)
	}

	client, err := r.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if err := r.authenticate(client, m.Mailbox.Address, token.AccessToken); err != nil {
		return err
	}
	return r.deliver(client, m)
}

func (r *Relay) connect(ctx context.Context) (*smtp.Client, error) {
	address := net.JoinHostPort(r.opts.Host, strconv.Itoa(r.opts.Port))

	conn, err := r.opts.Dial(ctx, "tcp", address)
	if err != nil {
		return nil, transport.NewTransient("net", "could not connect to "+address+": "+err.Error(), err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	tlsConfig := r.opts.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{ServerName: r.opts.Host, MinVersion: tls.VersionTLS12}
	}

	// Submission to Exchange Online is always over STARTTLS. go-smtp performs
	// the greeting and the upgrade together, and there is deliberately no
	// fallback to an unencrypted session: the alternative to TLS here is
	// sending a bearer token in clear text.
	client, err := smtp.NewClientStartTLS(conn, tlsConfig)
	if err != nil {
		_ = conn.Close()
		return nil, classify(err, "STARTTLS failed")
	}

	// Re-greet with the configured name now that the session is encrypted; the
	// EHLO after STARTTLS is the one the server records.
	if err := client.Hello(r.opts.LocalName); err != nil {
		_ = client.Close()
		return nil, classify(err, "EHLO failed")
	}
	return client, nil
}

func (r *Relay) authenticate(client *smtp.Client, mailbox, accessToken string) error {
	if ok := client.SupportsAuth(oauth.XOAuth2); !ok {
		return transport.NewTransient("smtp",
			"the server does not offer AUTH XOAUTH2 after STARTTLS", nil)
	}

	initial, err := oauth.BuildXOAuth2(mailbox, accessToken)
	if err != nil {
		return transport.NewPermanent("xoauth2", err.Error(), err)
	}

	if err := client.Auth(&xoauth2Client{initial: initial}); err != nil {
		return classifyAuth(err, mailbox)
	}
	return nil
}

func (r *Relay) deliver(client *smtp.Client, m *transport.Message) error {
	if err := client.Mail(m.EnvelopeFrom(), nil); err != nil {
		return classify(err, "MAIL FROM was rejected")
	}
	for _, rcpt := range m.Recipients {
		if err := client.Rcpt(rcpt, nil); err != nil {
			return classify(err, "RCPT TO "+rcpt+" was rejected")
		}
	}

	w, err := client.Data()
	if err != nil {
		return classify(err, "DATA was rejected")
	}
	if _, err := w.Write(m.Raw); err != nil {
		_ = w.Close()
		return transport.NewTransient("net", "the connection failed while sending the message: "+err.Error(), err)
	}
	// The server's verdict on the message arrives when the data stream closes.
	if err := w.Close(); err != nil {
		return classify(err, "the message was rejected")
	}

	if err := client.Quit(); err != nil {
		// The message was already accepted; a failure to say goodbye politely
		// must not turn a delivered message into a retry.
		r.opts.Log.Debug("upstream QUIT failed after a successful delivery",
			"message_id", m.ID, "reason", err)
	}
	return nil
}

// xoauth2Client is the SASL client side of XOAUTH2. The whole exchange is a
// single initial response; if the server disagrees it sends a challenge
// containing a JSON error, which must be answered with an empty response before
// the real status arrives.
type xoauth2Client struct {
	initial []byte
	done    bool
}

func (c *xoauth2Client) Start() (mech string, ir []byte, err error) {
	return oauth.XOAuth2, c.initial, nil
}

func (c *xoauth2Client) Next(_ []byte) ([]byte, error) {
	if c.done {
		return nil, errors.New("smtprelay: unexpected additional XOAUTH2 challenge")
	}
	c.done = true
	// An empty response tells the server to report the failure as a status code.
	return []byte{}, nil
}

// ensure the SASL interface is satisfied.
var _ sasl.Client = (*xoauth2Client)(nil)

// classify turns an SMTP error into a transport.Error.
//
// 4xx is temporary and 5xx is permanent, per RFC 5321. The exception worth
// naming is 4.7.500 "Server busy", which Exchange Online returns when a mailbox
// exceeds its 30 messages/minute budget — the queue's own rate limiting exists
// to keep that from happening, and when it does the right response is to back
// off rather than to try harder.
func classify(err error, what string) error {
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) {
		return transport.NewTransient("net", what+": "+err.Error(), err)
	}

	code := enhancedOrNumeric(smtpErr)
	message := what + ": " + strings.TrimSpace(smtpErr.Message)

	if smtpErr.Code >= 500 {
		return transport.NewPermanent(code, message, err)
	}
	return transport.NewTransient(code, message, err)
}

// classifyAuth handles an authentication rejection, which needs its own message
// because a bare "535 5.7.3 Authentication unsuccessful" gives an operator
// nothing to act on.
func classifyAuth(err error, mailbox string) error {
	var smtpErr *smtp.SMTPError
	code := "535"
	message := err.Error()
	if errors.As(err, &smtpErr) {
		code = enhancedOrNumeric(smtpErr)
		message = strings.TrimSpace(smtpErr.Message)
	}
	return transport.NewAuthFailure(code,
		fmt.Sprintf("authenticating as %s failed: %s", mailbox, message), err)
}

// enhancedOrNumeric prefers the enhanced status, which is what Microsoft's
// documentation indexes by.
func enhancedOrNumeric(err *smtp.SMTPError) string {
	if err.EnhancedCode != smtp.EnhancedCodeNotSet {
		return fmt.Sprintf("%d.%d.%d", err.EnhancedCode[0], err.EnhancedCode[1], err.EnhancedCode[2])
	}
	return strconv.Itoa(err.Code)
}
