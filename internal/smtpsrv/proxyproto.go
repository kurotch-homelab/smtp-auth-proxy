package smtpsrv

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// PROXY protocol support.
//
// A Kubernetes Service of type LoadBalancer, or an nginx TCP passthrough, hides
// the real client address behind the proxy's own. Without the original address
// the per-account CIDR restrictions would compare every device against the load
// balancer, which is the same as having no restriction at all.
//
// A PROXY header is only honored from a network the operator listed as trusted.
// Accepting one from anywhere would let any client claim any source address and
// walk straight through those same restrictions.

// PROXY protocol errors.
var (
	// ErrProxyUntrusted means a PROXY header arrived from a peer that is not on
	// the trusted list.
	ErrProxyUntrusted = errors.New("smtpsrv: PROXY header from an untrusted peer")
	// ErrProxyMalformed means the header could not be parsed.
	ErrProxyMalformed = errors.New("smtpsrv: malformed PROXY header")
)

var (
	proxyV1Prefix = []byte("PROXY ")
	proxyV2Sig    = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

const (
	// proxyReadTimeout bounds how long a connection may take to send its
	// header, so a peer that opens a socket and says nothing cannot pin a slot.
	proxyReadTimeout = 10 * time.Second
	// proxyV1MaxLen is the longest a version 1 header can be, per the spec.
	proxyV1MaxLen    = 107
	proxyV2HeaderLen = 16
)

// proxyHandshake reads a PROXY header from trusted peers so the connection can
// report the original client address as its RemoteAddr.
type proxyHandshake struct {
	trusted []*net.IPNet
}

// newProxyHandshake validates the trusted networks up front.
func newProxyHandshake(trustedCIDRs []string) (*proxyHandshake, error) {
	trusted := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, c := range trustedCIDRs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("smtpsrv: invalid trusted network %q: %w", c, err)
		}
		trusted = append(trusted, network)
	}
	if len(trusted) == 0 {
		return nil, errors.New("smtpsrv: PROXY protocol needs at least one trusted network")
	}
	return &proxyHandshake{trusted: trusted}, nil
}

// accept performs the handshake on one connection.
func (l *proxyHandshake) accept(conn net.Conn) (net.Conn, error) {
	return l.handshake(conn)
}

func (l *proxyHandshake) trusts(addr net.Addr) bool {
	ip := remoteIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range l.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (l *proxyHandshake) handshake(conn net.Conn) (net.Conn, error) {
	br := bufio.NewReader(conn)

	if err := conn.SetReadDeadline(time.Now().Add(proxyReadTimeout)); err != nil {
		return nil, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	// Peek at enough bytes to recognize either version without consuming them.
	peeked, err := br.Peek(len(proxyV2Sig))
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, err
	}

	hasV1 := len(peeked) >= len(proxyV1Prefix) && bytes.Equal(peeked[:len(proxyV1Prefix)], proxyV1Prefix)
	hasV2 := len(peeked) >= len(proxyV2Sig) && bytes.Equal(peeked, proxyV2Sig)

	if !hasV1 && !hasV2 {
		// No header. That is fine — a health check or a direct client — as long
		// as we simply use the peer address.
		return &bufferedConn{Conn: conn, reader: br}, nil
	}
	if !l.trusts(conn.RemoteAddr()) {
		return nil, fmt.Errorf("%w: %s", ErrProxyUntrusted, addrKey(conn.RemoteAddr()))
	}

	var source net.Addr
	if hasV1 {
		source, err = parseProxyV1(br)
	} else {
		source, err = parseProxyV2(br)
	}
	if err != nil {
		return nil, err
	}

	return &bufferedConn{Conn: conn, reader: br, remote: source}, nil
}

// parseProxyV1 reads the human-readable form:
//
//	PROXY TCP4 192.0.2.1 198.51.100.1 56324 587\r\n
func parseProxyV1(br *bufio.Reader) (net.Addr, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProxyMalformed, err)
	}
	if len(line) > proxyV1MaxLen {
		return nil, fmt.Errorf("%w: version 1 header is %d bytes", ErrProxyMalformed, len(line))
	}

	fields := splitFields(line)
	// "PROXY UNKNOWN" means the proxy could not determine the origin; fall back
	// to the peer address rather than inventing one.
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return nil, nil
	}
	if len(fields) != 6 || fields[0] != "PROXY" {
		return nil, fmt.Errorf("%w: %q", ErrProxyMalformed, line)
	}

	ip := net.ParseIP(fields[2])
	if ip == nil {
		return nil, fmt.Errorf("%w: source address %q", ErrProxyMalformed, fields[2])
	}
	port, err := strconv.Atoi(fields[4])
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("%w: source port %q", ErrProxyMalformed, fields[4])
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

// parseProxyV2 reads the binary form.
func parseProxyV2(br *bufio.Reader) (net.Addr, error) {
	header := make([]byte, proxyV2HeaderLen)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProxyMalformed, err)
	}

	versionCommand := header[12]
	if versionCommand>>4 != 2 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrProxyMalformed, versionCommand>>4)
	}
	command := versionCommand & 0x0F
	family := header[13]
	length := int(binary.BigEndian.Uint16(header[14:16]))

	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProxyMalformed, err)
	}

	// LOCAL (0x00) means the connection is the proxy's own, e.g. a health
	// check; there is no original client to report.
	if command == 0x00 {
		return nil, nil
	}
	if command != 0x01 {
		return nil, fmt.Errorf("%w: unsupported command %d", ErrProxyMalformed, command)
	}

	switch family {
	case 0x11, 0x12: // TCP or UDP over IPv4
		if len(body) < 12 {
			return nil, fmt.Errorf("%w: IPv4 body is %d bytes", ErrProxyMalformed, len(body))
		}
		return &net.TCPAddr{IP: net.IP(body[0:4]), Port: int(binary.BigEndian.Uint16(body[8:10]))}, nil
	case 0x21, 0x22: // TCP or UDP over IPv6
		if len(body) < 36 {
			return nil, fmt.Errorf("%w: IPv6 body is %d bytes", ErrProxyMalformed, len(body))
		}
		return &net.TCPAddr{IP: net.IP(body[0:16]), Port: int(binary.BigEndian.Uint16(body[32:34]))}, nil
	case 0x00: // UNSPEC
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: unsupported address family 0x%02x", ErrProxyMalformed, family)
	}
}

// splitFields splits on spaces, ignoring the trailing CRLF.
func splitFields(line string) []string {
	trimmed := strings.TrimRight(line, "\r\n")

	var out []string
	start := -1
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == ' ' {
			if start >= 0 {
				out = append(out, trimmed[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, trimmed[start:])
	}
	return out
}

// bufferedConn keeps the bytes peeked during the handshake and, when a PROXY
// header supplied one, reports the original client as RemoteAddr.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
	remote net.Addr
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}
