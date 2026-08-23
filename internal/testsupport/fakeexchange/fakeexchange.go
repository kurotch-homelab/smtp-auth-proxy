// Package fakeexchange is a stand-in for Exchange Online's SMTP submission
// endpoint, for tests that need to exercise the whole delivery path without a
// tenant.
//
// It speaks enough of the protocol to be convincing: STARTTLS, AUTH XOAUTH2,
// and the enhanced status codes Exchange actually returns — including
// "4.7.500 Server busy", which is what a mailbox over its rate budget sees.
package fakeexchange

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
)

// Delivery is one message the fake accepted.
type Delivery struct {
	// AuthUser is the mailbox from the XOAUTH2 "user=" field.
	AuthUser string
	// AuthToken is the bearer token from the XOAUTH2 string.
	AuthToken string
	// RawXOAuth2 is the decoded SASL response, so a test can assert on the
	// exact byte layout rather than on what the parser made of it.
	RawXOAuth2 []byte

	EnvelopeFrom string
	Recipients   []string
	Data         string
}

// Behavior makes the fake reject at a chosen point.
type Behavior struct {
	// RejectAuth fails AUTH with 535 5.7.3, as Exchange does when the tenant
	// configuration is incomplete.
	RejectAuth bool
	// RejectMailFrom, RejectRcptTo and RejectData carry an SMTP response line
	// such as "550 5.7.1 Access denied" to send instead of accepting.
	RejectMailFrom string
	RejectRcptTo   string
	RejectData     string
	// FailAfterDeliveries starts rejecting DATA with "451 4.7.500 Server busy"
	// once this many messages have been accepted; zero means never.
	FailAfterDeliveries int
}

// Server is a running fake.
type Server struct {
	listener net.Listener
	tlsConf  *tls.Config

	mu         sync.Mutex
	deliveries []Delivery
	behavior   Behavior

	wg     sync.WaitGroup
	closed chan struct{}
}

// Start brings up a fake on an ephemeral port and stops it with the test.
func Start(t *testing.T, tlsCert tls.Certificate) *Server {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeexchange: listen: %v", err)
	}

	s := &Server{
		listener: ln,
		tlsConf:  &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
		closed:   make(chan struct{}),
	}

	s.wg.Add(1)
	go s.acceptLoop()

	t.Cleanup(s.Stop)
	return s
}

// Addr is the fake's host:port.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Host and Port split Addr for callers that configure them separately.
func (s *Server) Host() string {
	host, _, _ := net.SplitHostPort(s.Addr())
	return host
}

func (s *Server) Port() int {
	_, port, _ := net.SplitHostPort(s.Addr())
	var n int
	_, _ = fmt.Sscanf(port, "%d", &n)
	return n
}

// SetBehavior changes how the fake responds.
func (s *Server) SetBehavior(b Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.behavior = b
}

// Deliveries returns everything accepted so far.
func (s *Server) Deliveries() []Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Delivery(nil), s.deliveries...)
}

// Stop shuts the fake down.
func (s *Server) Stop() {
	select {
	case <-s.closed:
		return
	default:
	}
	close(s.closed)
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				return
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { _ = conn.Close() }()
			s.handle(conn)
		}()
	}
}
