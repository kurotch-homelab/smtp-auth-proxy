package smtpsrv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/policy"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/version"
)

// session handles one client connection.
//
// go-smtp calls the methods below as the client issues commands, always from a
// single goroutine per connection, so the fields need no locking.
type session struct {
	server *Server
	conn   *smtp.Conn

	remote net.Addr
	// identity is nil until AUTH succeeds.
	identity *Identity
	// authFailures closes the connection once it reaches the configured limit,
	// so a password-guessing client cannot keep one socket forever.
	authFailures int

	// Per-message state, cleared by Reset.
	envelopeFrom policy.Address
	recipients   []string
}

// AuthMechanisms lists what the server offers.
//
// AUTH is not advertised on an unencrypted connection: PLAIN and LOGIN both
// send the password in the clear, and a client that sees no AUTH will not try.
// An operator with a device that cannot do TLS at all can opt out explicitly.
func (s *session) AuthMechanisms() []string {
	if !s.encrypted() && !s.server.allowInsecureAuth {
		return nil
	}
	return []string{sasl.Plain, sasl.Login}
}

// Auth returns the SASL server for a mechanism.
func (s *session) Auth(mech string) (sasl.Server, error) {
	if !s.encrypted() && !s.server.allowInsecureAuth {
		return nil, &smtp.SMTPError{
			Code:         538,
			EnhancedCode: smtp.EnhancedCode{5, 7, 11},
			Message:      "Encryption required for requested authentication mechanism",
		}
	}
	return s.saslServers(mech)
}

// encrypted reports whether the connection is protected.
//
// This works for both listener styles because TLS is applied outermost: on an
// implicit-TLS listener the socket is a *tls.Conn before go-smtp ever sees it,
// and on a STARTTLS listener go-smtp performs the upgrade itself.
func (s *session) encrypted() bool {
	_, ok := s.conn.TLSConnectionState()
	return ok
}

// authenticate is the shared body of every SASL mechanism.
func (s *session) authenticate(username, password string) error {
	ctx, cancel := context.WithTimeout(s.server.baseContext(), s.server.authTimeout)
	defer cancel()

	identity, err := s.server.auth.Authenticate(ctx, username, password, remoteIP(s.remote))
	if err != nil {
		s.recordAuthFailure(username, err)
		return ErrAuthFailed
	}

	s.identity = identity
	s.server.log.Info("smtp authentication succeeded",
		"username", identity.Username,
		"account_id", identity.AccountID,
		"remote", addrKey(s.remote),
		"tls", s.encrypted(),
	)
	return nil
}

// recordAuthFailure logs the real reason and counts the attempt. The client
// only ever sees ErrAuthFailed.
func (s *session) recordAuthFailure(username string, err error) {
	s.authFailures++
	s.server.log.Warn("smtp authentication failed",
		"username", username,
		"remote", addrKey(s.remote),
		"tls", s.encrypted(),
		"attempt", s.authFailures,
		"reason", err,
	)

	if s.server.maxAuthFailures > 0 && s.authFailures >= s.server.maxAuthFailures {
		// Dropping the connection turns an online guessing attack into one that
		// has to pay for a new TCP handshake and TLS negotiation per attempt.
		s.server.log.Warn("closing connection after repeated authentication failures",
			"remote", addrKey(s.remote), "failures", s.authFailures)
		// The client is being dropped mid-exchange; a close error here tells us
		// nothing actionable.
		_ = s.conn.Close()
	}
}

// Mail handles MAIL FROM.
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.identity == nil {
		return errAuthRequired()
	}
	if s.server.requireTLS && !s.encrypted() {
		return &smtp.SMTPError{
			Code:         530,
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
			Message:      "Must issue a STARTTLS command first",
		}
	}

	addr, err := policy.ParseAddress(from)
	if err != nil {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 7},
			Message:      "Bad sender address syntax",
		}
	}

	s.envelopeFrom = addr
	s.recipients = nil
	return nil
}

// Rcpt handles RCPT TO.
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.identity == nil {
		return errAuthRequired()
	}
	if len(s.recipients) >= s.server.maxRecipients {
		return &smtp.SMTPError{
			Code:         452,
			EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message:      fmt.Sprintf("Too many recipients; this server accepts at most %d", s.server.maxRecipients),
		}
	}

	addr, err := policy.ParseAddress(to)
	if err != nil || addr.IsEmpty() {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Bad recipient address syntax",
		}
	}

	s.recipients = append(s.recipients, addr.Original)
	return nil
}

// Data reads the message, applies the sender policy and queues it.
func (s *session) Data(r io.Reader) error {
	if s.identity == nil {
		return errAuthRequired()
	}
	if len(s.recipients) == 0 {
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}

	raw, err := s.readMessage(r)
	if err != nil {
		return err
	}

	parsed, err := parseMessage(raw)
	if err != nil {
		s.server.log.Warn("rejecting an unparseable message",
			"username", s.identity.Username, "remote", addrKey(s.remote), "reason", err)
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 6, 0},
			Message:      "Message could not be parsed: " + err.Error(),
		}
	}

	headerFrom, err := policy.ParseHeaderFrom(parsed.Get("From"))
	if err != nil && !errors.Is(err, policy.ErrNoAddress) {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Bad From header: " + err.Error(),
		}
	}

	decision := policy.Resolve(policy.Input{
		Account:      s.identity.Account,
		Mailboxes:    s.identity.Mailboxes,
		EnvelopeFrom: s.envelopeFrom,
		HeaderFrom:   headerFrom,
	})
	if decision.Rejected() {
		s.server.log.Warn("rejecting a submission",
			"username", s.identity.Username,
			"remote", addrKey(s.remote),
			"header_from", headerFrom.Normalized,
			"reason", decision.Reason,
		)
		return &smtp.SMTPError{
			Code:         decision.Code,
			EnhancedCode: parseEnhanced(decision.Enhanced),
			Message:      decision.Reason,
		}
	}

	final, finalFrom := s.applyDecision(parsed, decision, headerFrom)

	sub := &Submission{
		Identity:     s.identity,
		Mailbox:      decision.Mailbox,
		EnvelopeFrom: s.envelopeFrom,
		HeaderFrom:   finalFrom,
		Recipients:   s.recipients,
		Raw:          final,
		MessageID:    strings.Trim(parsed.Get("Message-Id"), "<>"),
		ClientIP:     remoteIP(s.remote),
		ClientHelo:   s.conn.Hostname(),
		TLS:          s.encrypted(),
		ReceivedAt:   time.Now().UTC(),
	}
	if s.server.recordSubjects {
		sub.Subject = parsed.Get("Subject")
	}

	ctx, cancel := context.WithTimeout(s.server.baseContext(), s.server.submitTimeout)
	defer cancel()

	id, err := s.server.submitter.Submit(ctx, sub)
	if err != nil {
		s.server.log.Error("failed to queue a submission",
			"username", s.identity.Username, "reason", err)
		// A 4xx tells the client to retry, which is right: the message was
		// valid and the failure is ours.
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Could not queue the message; please retry",
		}
	}

	s.server.log.Info("queued a submission",
		"message_id", id,
		"username", s.identity.Username,
		"mailbox", decision.Mailbox.Address,
		"recipients", len(s.recipients),
		"bytes", len(final),
		"action", decision.Action,
	)
	return nil
}

// readMessage reads the DATA payload, enforcing the size limit.
//
// go-smtp already caps MaxMessageBytes, but the reader must be fully consumed
// before Data returns or the connection desynchronizes, so the limit is
// enforced here too and the remainder drained.
func (s *session) readMessage(r io.Reader) ([]byte, error) {
	limit := s.server.maxMessageBytes
	buf := make([]byte, 0, 64*1024)
	limited := io.LimitReader(r, limit+1)

	chunk := make([]byte, 32*1024)
	for {
		n, err := limited.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 4, 2},
				Message:      "Connection error while reading the message",
			}
		}
		if int64(len(buf)) > limit {
			_, _ = io.Copy(io.Discard, r)
			return nil, &smtp.SMTPError{
				Code:         552,
				EnhancedCode: smtp.EnhancedCode{5, 3, 4},
				Message:      fmt.Sprintf("Message exceeds the %d byte limit", limit),
			}
		}
	}
	return buf, nil
}

// applyDecision rewrites headers according to the policy and stamps a Received
// header, returning the final message and the From address it now carries.
func (s *session) applyDecision(parsed *message, d policy.Decision, headerFrom policy.Address) ([]byte, policy.Address) {
	edits := []headerEdit{{Key: "Received", Value: s.receivedHeader(), Prepend: true}}
	finalFrom := headerFrom

	if d.Action == policy.ActionRewrite {
		edits = append(edits,
			headerEdit{Key: "From", Value: d.RewriteFrom},
			// Keep the original reachable: without this a reply would go to the
			// shared mailbox rather than to whoever actually sent the message.
			headerEdit{Key: "X-Original-From", Value: headerFrom.String()},
		)
		if parsed.Get("Reply-To") == "" && !headerFrom.IsEmpty() {
			edits = append(edits, headerEdit{Key: "Reply-To", Value: headerFrom.String()})
		}
		finalFrom = policy.MustParseAddress(d.RewriteFrom)
	}

	return parsed.rewriteHeaders(edits), finalFrom
}

// receivedHeader renders the trace header this hop adds.
func (s *session) receivedHeader() string {
	var b strings.Builder

	b.WriteString("from ")
	if helo := s.conn.Hostname(); helo != "" {
		b.WriteString(sanitizeHeaderValue(helo))
	} else {
		b.WriteString("unknown")
	}
	if ip := remoteIP(s.remote); ip != nil {
		fmt.Fprintf(&b, " (%s)", ip)
	}

	fmt.Fprintf(&b, " by %s (%s) with ", s.server.hostname, version.UserAgent())
	if s.encrypted() {
		b.WriteString("ESMTPSA")
	} else {
		b.WriteString("ESMTPA")
	}
	fmt.Fprintf(&b, " id %s; %s", s.identity.Username, time.Now().UTC().Format(time.RFC1123Z))

	return b.String()
}

// Reset discards the current message. AUTH state survives, as SMTP requires.
func (s *session) Reset() {
	s.envelopeFrom = policy.Address{}
	s.recipients = nil
}

// Logout releases the session.
func (s *session) Logout() error {
	s.Reset()
	return nil
}

func errAuthRequired() error {
	return &smtp.SMTPError{
		Code:         530,
		EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		Message:      "Authentication required",
	}
}

// parseEnhanced turns "5.7.1" into the triple go-smtp wants.
func parseEnhanced(s string) smtp.EnhancedCode {
	var code smtp.EnhancedCode
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return smtp.EnhancedCodeNotSet
	}
	for i, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return smtp.EnhancedCodeNotSet
			}
			n = n*10 + int(c-'0')
		}
		code[i] = n
	}
	return code
}
