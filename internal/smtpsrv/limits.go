package smtpsrv

import (
	"net"
	"sync"
)

// connLimiter caps how many connections one client address may hold at once.
//
// Exchange Online allows three concurrent submissions per mailbox, so a single
// misbehaving device opening a hundred connections would starve every other
// service on the LAN long before it reached the proxy's own limits.
type connLimiter struct {
	mu     sync.Mutex
	perIP  map[string]int
	total  int
	maxIP  int
	maxAll int
}

func newConnLimiter(maxPerIP, maxTotal int) *connLimiter {
	return &connLimiter{
		perIP:  make(map[string]int),
		maxIP:  maxPerIP,
		maxAll: maxTotal,
	}
}

// acquire reserves a slot, returning false when a limit is already reached.
func (l *connLimiter) acquire(addr net.Addr) bool {
	key := addrKey(addr)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxAll > 0 && l.total >= l.maxAll {
		return false
	}
	if l.maxIP > 0 && l.perIP[key] >= l.maxIP {
		return false
	}
	l.perIP[key]++
	l.total++
	return true
}

// release returns a slot.
func (l *connLimiter) release(addr net.Addr) {
	key := addrKey(addr)

	l.mu.Lock()
	defer l.mu.Unlock()

	if n := l.perIP[key]; n <= 1 {
		delete(l.perIP, key)
	} else {
		l.perIP[key] = n - 1
	}
	if l.total > 0 {
		l.total--
	}
}

// counts reports the current usage, for metrics and tests.
func (l *connLimiter) counts() (total, distinctIPs int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.perIP)
}

// addrKey reduces an address to the client host, so several connections from
// one device count together regardless of source port.
func addrKey(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// remoteIP extracts the client IP from an address, or nil.
func remoteIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return net.ParseIP(addr.String())
	}
	return net.ParseIP(host)
}
