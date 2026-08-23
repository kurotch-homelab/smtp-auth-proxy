package fakeexchange

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strings"
	"time"
)

// session is one client connection to the fake.
type session struct {
	server *Server
	conn   net.Conn
	rw     *bufio.ReadWriter

	authenticated bool
	current       Delivery
}

const sessionTimeout = 30 * time.Second

func (s *Server) handle(conn net.Conn) {
	sess := &session{
		server: s,
		conn:   conn,
		rw:     bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
	sess.run()
}

func (s *session) run() {
	s.write("220 fake.outlook.example ESMTP")

	for {
		_ = s.conn.SetDeadline(time.Now().Add(sessionTimeout))

		line, err := s.rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		verb, args := splitCommand(line)
		switch strings.ToUpper(verb) {
		case "EHLO", "LHLO":
			s.ehlo()
		case "HELO":
			s.write("250 fake.outlook.example")
		case "STARTTLS":
			if !s.startTLS() {
				return
			}
		case "AUTH":
			s.auth(args)
		case "MAIL":
			s.mail(args)
		case "RCPT":
			s.rcpt(args)
		case "DATA":
			s.data()
		case "RSET":
			s.current = Delivery{AuthUser: s.current.AuthUser, AuthToken: s.current.AuthToken, RawXOAuth2: s.current.RawXOAuth2}
			s.write("250 2.0.0 Ok")
		case "NOOP":
			s.write("250 2.0.0 Ok")
		case "QUIT":
			s.write("221 2.0.0 Service closing transmission channel")
			return
		default:
			s.write("500 5.5.1 Unrecognized command")
		}
	}
}

func (s *session) ehlo() {
	_, isTLS := s.conn.(*tls.Conn)

	lines := []string{"250-fake.outlook.example", "250-SIZE 157286400", "250-8BITMIME"}
	if isTLS {
		// Exchange Online only offers AUTH after the session is encrypted.
		lines = append(lines, "250-AUTH XOAUTH2 LOGIN")
	} else {
		lines = append(lines, "250-STARTTLS")
	}
	lines = append(lines, "250 SMTPUTF8")

	for _, l := range lines {
		s.write(l)
	}
}

func (s *session) startTLS() bool {
	s.write("220 2.0.0 SMTP server ready")

	tlsConn := tls.Server(s.conn, s.server.tlsConf)
	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}
	s.conn = tlsConn
	s.rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
	return true
}

func (s *session) auth(args string) {
	mech, initial := splitCommand(args)
	if !strings.EqualFold(mech, "XOAUTH2") {
		s.write("504 5.7.4 Unrecognized authentication type")
		return
	}
	if _, isTLS := s.conn.(*tls.Conn); !isTLS {
		s.write("530 5.7.0 Must issue a STARTTLS command first")
		return
	}

	if initial == "" {
		s.write("334 ")
		line, err := s.rw.ReadString('\n')
		if err != nil {
			return
		}
		initial = strings.TrimRight(line, "\r\n")
	}

	raw, err := base64.StdEncoding.DecodeString(initial)
	if err != nil {
		s.write("501 5.5.2 Cannot decode response")
		return
	}

	user, token, ok := parseXOAuth2(raw)
	if !ok {
		s.write("535 5.7.3 Authentication unsuccessful")
		return
	}

	s.server.mu.Lock()
	reject := s.server.behavior.RejectAuth
	s.server.mu.Unlock()

	if reject {
		// Exchange answers a bad XOAUTH2 with a base64 JSON challenge first,
		// then the real status once the client sends an empty response.
		s.write("334 eyJzdGF0dXMiOiI0MDEiLCJzY2hlbWVzIjoiQmVhcmVyIn0=")
		if _, err := s.rw.ReadString('\n'); err != nil {
			return
		}
		s.write("535 5.7.3 Authentication unsuccessful")
		return
	}

	s.authenticated = true
	s.current.AuthUser = user
	s.current.AuthToken = token
	s.current.RawXOAuth2 = raw
	s.write("235 2.7.0 Authentication successful")
}

func (s *session) mail(args string) {
	if !s.authenticated {
		s.write("530 5.7.0 Authentication required")
		return
	}

	s.server.mu.Lock()
	reject := s.server.behavior.RejectMailFrom
	s.server.mu.Unlock()
	if reject != "" {
		s.write(reject)
		return
	}

	s.current.EnvelopeFrom = extractAddress(args, "FROM:")
	s.current.Recipients = nil
	s.write("250 2.1.0 Sender OK")
}

func (s *session) rcpt(args string) {
	if !s.authenticated {
		s.write("530 5.7.0 Authentication required")
		return
	}

	s.server.mu.Lock()
	reject := s.server.behavior.RejectRcptTo
	s.server.mu.Unlock()
	if reject != "" {
		s.write(reject)
		return
	}

	s.current.Recipients = append(s.current.Recipients, extractAddress(args, "TO:"))
	s.write("250 2.1.5 Recipient OK")
}

func (s *session) data() {
	if !s.authenticated {
		s.write("530 5.7.0 Authentication required")
		return
	}

	s.server.mu.Lock()
	rejectData := s.server.behavior.RejectData
	busyAfter := s.server.behavior.FailAfterDeliveries
	accepted := len(s.server.deliveries)
	s.server.mu.Unlock()

	if rejectData != "" {
		s.write(rejectData)
		return
	}

	s.write("354 Start mail input; end with <CRLF>.<CRLF>")

	var body strings.Builder
	for {
		line, err := s.rw.ReadString('\n')
		if err != nil {
			return
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
		// Undo dot-stuffing.
		body.WriteString(strings.TrimPrefix(line, "."))
	}

	if busyAfter > 0 && accepted >= busyAfter {
		// What a mailbox over its 30 messages/minute budget actually sees.
		s.write("451 4.7.500 Server busy, please try again later")
		return
	}

	s.current.Data = body.String()

	s.server.mu.Lock()
	s.server.deliveries = append(s.server.deliveries, s.current)
	s.server.mu.Unlock()

	s.current.EnvelopeFrom = ""
	s.current.Recipients = nil
	s.current.Data = ""
	s.write("250 2.0.0 OK <fake-message-id>")
}

func (s *session) write(line string) {
	_, _ = s.rw.WriteString(line + "\r\n")
	_ = s.rw.Flush()
}

// parseXOAuth2 splits "user=<mailbox>\x01auth=Bearer <token>\x01\x01".
func parseXOAuth2(raw []byte) (user, token string, ok bool) {
	parts := strings.Split(string(raw), "\x01")
	for _, p := range parts {
		switch {
		case strings.HasPrefix(p, "user="):
			user = strings.TrimPrefix(p, "user=")
		case strings.HasPrefix(p, "auth=Bearer "):
			token = strings.TrimPrefix(p, "auth=Bearer ")
		}
	}
	return user, token, user != "" && token != ""
}

func splitCommand(line string) (verb, args string) {
	trimmed := strings.TrimSpace(line)
	if i := strings.IndexByte(trimmed, ' '); i >= 0 {
		return trimmed[:i], strings.TrimSpace(trimmed[i+1:])
	}
	return trimmed, ""
}

// extractAddress pulls the path out of "FROM:<a@example.com> SIZE=123".
func extractAddress(args, prefix string) string {
	upper := strings.ToUpper(args)
	i := strings.Index(upper, prefix)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(args[i+len(prefix):])
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	return strings.Trim(rest, "<>")
}
