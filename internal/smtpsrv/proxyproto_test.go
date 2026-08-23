package smtpsrv

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseProxyV1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		line     string
		wantIP   string
		wantPort int
		wantNil  bool
		wantErr  bool
	}{
		{
			name:   "IPv4",
			line:   "PROXY TCP4 192.0.2.10 198.51.100.5 56324 587\r\n",
			wantIP: "192.0.2.10", wantPort: 56324,
		},
		{
			name:   "IPv6",
			line:   "PROXY TCP6 2001:db8::1 2001:db8::2 56324 587\r\n",
			wantIP: "2001:db8::1", wantPort: 56324,
		},
		{
			// The proxy could not determine the origin, so there is no client
			// address to report and the peer address stands.
			name: "UNKNOWN", line: "PROXY UNKNOWN\r\n", wantNil: true,
		},
		{name: "wrong field count", line: "PROXY TCP4 192.0.2.10 587\r\n", wantErr: true},
		{name: "not a PROXY line", line: "HELO example.com\r\n", wantErr: true},
		{name: "bad source address", line: "PROXY TCP4 not-an-ip 198.51.100.5 1 2\r\n", wantErr: true},
		{name: "bad source port", line: "PROXY TCP4 192.0.2.10 198.51.100.5 abc 587\r\n", wantErr: true},
		{name: "port out of range", line: "PROXY TCP4 192.0.2.10 198.51.100.5 99999 587\r\n", wantErr: true},
		{
			name:    "overlong header",
			line:    "PROXY TCP4 " + strings.Repeat("9", 120) + "\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			addr, err := parseProxyV1(bufio.NewReader(strings.NewReader(tt.line)))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProxyV1(%q) = %v, want an error", tt.line, addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyV1(%q): %v", tt.line, err)
			}
			if tt.wantNil {
				if addr != nil {
					t.Errorf("= %v, want nil", addr)
				}
				return
			}

			tcp, ok := addr.(*net.TCPAddr)
			if !ok {
				t.Fatalf("= %T, want *net.TCPAddr", addr)
			}
			if !tcp.IP.Equal(net.ParseIP(tt.wantIP)) || tcp.Port != tt.wantPort {
				t.Errorf("= %v, want %s:%d", tcp, tt.wantIP, tt.wantPort)
			}
		})
	}
}

// proxyV2 builds a binary PROXY header.
func proxyV2(command, family byte, body []byte) []byte {
	header := make([]byte, 0, proxyV2HeaderLen+len(body))
	header = append(header, proxyV2Sig...)
	header = append(header, 0x20|command, family)
	header = binary.BigEndian.AppendUint16(header, uint16(len(body)))
	return append(header, body...)
}

func TestParseProxyV2(t *testing.T) {
	t.Parallel()

	ipv4Body := func() []byte {
		b := make([]byte, 12)
		copy(b[0:4], net.ParseIP("192.0.2.10").To4())
		copy(b[4:8], net.ParseIP("198.51.100.5").To4())
		binary.BigEndian.PutUint16(b[8:10], 56324)
		binary.BigEndian.PutUint16(b[10:12], 587)
		return b
	}()

	ipv6Body := func() []byte {
		b := make([]byte, 36)
		copy(b[0:16], net.ParseIP("2001:db8::1").To16())
		copy(b[16:32], net.ParseIP("2001:db8::2").To16())
		binary.BigEndian.PutUint16(b[32:34], 56324)
		binary.BigEndian.PutUint16(b[34:36], 587)
		return b
	}()

	tests := []struct {
		name    string
		raw     []byte
		wantIP  string
		wantNil bool
		wantErr bool
	}{
		{name: "IPv4 PROXY", raw: proxyV2(0x01, 0x11, ipv4Body), wantIP: "192.0.2.10"},
		{name: "IPv6 PROXY", raw: proxyV2(0x01, 0x21, ipv6Body), wantIP: "2001:db8::1"},
		// LOCAL is what a load balancer's own health check sends.
		{name: "LOCAL command", raw: proxyV2(0x00, 0x00, nil), wantNil: true},
		{name: "UNSPEC family", raw: proxyV2(0x01, 0x00, nil), wantNil: true},
		{name: "truncated IPv4 body", raw: proxyV2(0x01, 0x11, ipv4Body[:6]), wantErr: true},
		{name: "truncated IPv6 body", raw: proxyV2(0x01, 0x21, ipv6Body[:10]), wantErr: true},
		{name: "unsupported family", raw: proxyV2(0x01, 0x99, nil), wantErr: true},
		{name: "unsupported command", raw: proxyV2(0x07, 0x11, ipv4Body), wantErr: true},
		{name: "truncated header", raw: proxyV2Sig[:8], wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			addr, err := parseProxyV2(bufio.NewReader(bytes.NewReader(tt.raw)))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProxyV2 = %v, want an error", addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyV2: %v", err)
			}
			if tt.wantNil {
				if addr != nil {
					t.Errorf("= %v, want nil", addr)
				}
				return
			}
			tcp, ok := addr.(*net.TCPAddr)
			if !ok {
				t.Fatalf("= %T, want *net.TCPAddr", addr)
			}
			if !tcp.IP.Equal(net.ParseIP(tt.wantIP)) {
				t.Errorf("= %v, want %s", tcp.IP, tt.wantIP)
			}
		})
	}
}

func TestParseProxyV2RejectsVersion1Byte(t *testing.T) {
	t.Parallel()

	raw := proxyV2(0x01, 0x11, make([]byte, 12))
	raw[12] = 0x11 // version 1 in the high nibble
	if _, err := parseProxyV2(bufio.NewReader(bytes.NewReader(raw))); err == nil {
		t.Error("parseProxyV2 accepted a header claiming version 1")
	}
}

func TestNewProxyHandshakeValidatesNetworks(t *testing.T) {
	t.Parallel()

	if _, err := newProxyHandshake(nil); err == nil {
		t.Error("newProxyHandshake with no trusted networks = nil, want an error")
	}
	if _, err := newProxyHandshake([]string{"not-a-cidr"}); err == nil {
		t.Error("newProxyHandshake with a bad CIDR = nil, want an error")
	}
	if _, err := newProxyHandshake([]string{"10.0.0.0/8"}); err != nil {
		t.Errorf("newProxyHandshake = %v, want nil", err)
	}
}

// pipeConn is a net.Conn over an in-memory buffer with a settable peer address.
type pipeConn struct {
	net.Conn
	remote net.Addr
}

func (c *pipeConn) RemoteAddr() net.Addr { return c.remote }

// newPipe returns a connected pair where the server end reports peerAddr.
func newPipe(t *testing.T, peerAddr string) (client, server net.Conn) {
	t.Helper()

	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })

	addr, err := net.ResolveTCPAddr("tcp", peerAddr)
	if err != nil {
		t.Fatalf("resolving %q: %v", peerAddr, err)
	}
	return c, &pipeConn{Conn: s, remote: addr}
}

func TestProxyHandshakeAcceptsFromATrustedPeer(t *testing.T) {
	t.Parallel()

	client, server := newPipe(t, "10.0.0.1:40000")
	h, err := newProxyHandshake([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("newProxyHandshake: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 192.0.2.10 198.51.100.5 56324 587\r\nEHLO test\r\n"))
	}()

	conn, err := h.accept(server)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got := remoteIP(conn.RemoteAddr()); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("RemoteAddr = %v, want the address from the PROXY header", got)
	}

	// The bytes after the header must still be readable by the SMTP layer.
	buf := make([]byte, 11)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading past the header: %v", err)
	}
	if string(buf) != "EHLO test\r\n" {
		t.Errorf("read %q, want the SMTP command that followed the header", buf)
	}
}

// A PROXY header from an untrusted peer would let any client claim any source
// address, defeating the per-account CIDR restrictions entirely.
func TestProxyHandshakeRejectsAnUntrustedPeer(t *testing.T) {
	t.Parallel()

	client, server := newPipe(t, "203.0.113.9:40000")
	h, err := newProxyHandshake([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("newProxyHandshake: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 10.0.0.5 198.51.100.5 56324 587\r\n"))
	}()

	if _, err := h.accept(server); !errors.Is(err, ErrProxyUntrusted) {
		t.Errorf("accept = %v, want ErrProxyUntrusted", err)
	}
}

func TestProxyHandshakePassesThroughWithoutAHeader(t *testing.T) {
	t.Parallel()

	client, server := newPipe(t, "10.0.0.1:40000")
	h, err := newProxyHandshake([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("newProxyHandshake: %v", err)
	}

	go func() { _, _ = client.Write([]byte("EHLO example.com\r\n")) }()

	conn, err := h.accept(server)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	// No header means the peer address stands; a direct client or a health
	// check must not be refused.
	if got := remoteIP(conn.RemoteAddr()); !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("RemoteAddr = %v, want the peer address", got)
	}
}

func TestSplitFields(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"PROXY TCP4 a b 1 2\r\n": {"PROXY", "TCP4", "a", "b", "1", "2"},
		"  spaced   out  \r\n":   {"spaced", "out"},
		"single\n":               {"single"},
		"\r\n":                   nil,
		"":                       nil,
	}
	for in, want := range tests {
		got := splitFields(in)
		if len(got) != len(want) {
			t.Errorf("splitFields(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("splitFields(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}
