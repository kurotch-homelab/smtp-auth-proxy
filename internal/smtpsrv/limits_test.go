package smtpsrv

import (
	"net"
	"sync"
	"testing"
)

func tcpAddr(t *testing.T, s string) net.Addr {
	t.Helper()

	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("resolving %q: %v", s, err)
	}
	return a
}

func TestConnLimiterPerIP(t *testing.T) {
	t.Parallel()

	l := newConnLimiter(2, 100)
	a := tcpAddr(t, "10.0.0.1:1000")
	b := tcpAddr(t, "10.0.0.1:1001") // same host, different port
	c := tcpAddr(t, "10.0.0.2:1000")

	if !l.acquire(a) || !l.acquire(b) {
		t.Fatal("the first two connections from one host were refused")
	}
	// A third from the same host is over the limit, even from a new port.
	if l.acquire(tcpAddr(t, "10.0.0.1:1002")) {
		t.Error("a third connection from the same host was allowed")
	}
	// A different host is unaffected.
	if !l.acquire(c) {
		t.Error("a connection from a different host was refused")
	}

	l.release(a)
	if !l.acquire(tcpAddr(t, "10.0.0.1:1003")) {
		t.Error("a slot was not freed on release")
	}
}

func TestConnLimiterTotal(t *testing.T) {
	t.Parallel()

	l := newConnLimiter(10, 2)
	if !l.acquire(tcpAddr(t, "10.0.0.1:1")) || !l.acquire(tcpAddr(t, "10.0.0.2:1")) {
		t.Fatal("connections within the total limit were refused")
	}
	if l.acquire(tcpAddr(t, "10.0.0.3:1")) {
		t.Error("a connection past the total limit was allowed")
	}

	total, hosts := l.counts()
	if total != 2 || hosts != 2 {
		t.Errorf("counts() = (%d, %d), want (2, 2)", total, hosts)
	}
}

func TestConnLimiterZeroMeansUnlimited(t *testing.T) {
	t.Parallel()

	l := newConnLimiter(0, 0)
	for i := range 50 {
		if !l.acquire(tcpAddr(t, "10.0.0.1:1")) {
			t.Fatalf("connection %d was refused with limits disabled", i)
		}
	}
}

func TestConnLimiterReleasesCleanly(t *testing.T) {
	t.Parallel()

	l := newConnLimiter(5, 5)
	addr := tcpAddr(t, "10.0.0.1:1")

	l.acquire(addr)
	l.release(addr)
	// Releasing more than was acquired must not underflow into a state where
	// the limiter stops counting.
	l.release(addr)

	total, hosts := l.counts()
	if total != 0 || hosts != 0 {
		t.Errorf("counts() = (%d, %d), want (0, 0)", total, hosts)
	}
}

func TestConnLimiterIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	l := newConnLimiter(0, 0)
	var wg sync.WaitGroup

	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := tcpAddr(t, "10.0.0.1:1")
			for range 20 {
				if l.acquire(addr) {
					l.release(addr)
				}
			}
			_ = i
		}()
	}
	wg.Wait()

	if total, _ := l.counts(); total != 0 {
		t.Errorf("counts() = %d after balanced acquire/release, want 0", total)
	}
}

func TestAddrKey(t *testing.T) {
	t.Parallel()

	if got := addrKey(nil); got != "unknown" {
		t.Errorf("addrKey(nil) = %q, want unknown", got)
	}
	if got := addrKey(tcpAddr(t, "10.0.0.1:1234")); got != "10.0.0.1" {
		t.Errorf("addrKey = %q, want the host without the port", got)
	}
}

func TestRemoteIP(t *testing.T) {
	t.Parallel()

	if got := remoteIP(nil); got != nil {
		t.Errorf("remoteIP(nil) = %v, want nil", got)
	}
	if got := remoteIP(tcpAddr(t, "10.0.0.1:1234")); !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("remoteIP = %v, want 10.0.0.1", got)
	}
	if got := remoteIP(tcpAddr(t, "[2001:db8::1]:1234")); !got.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("remoteIP = %v, want 2001:db8::1", got)
	}
	// A non-TCP address must not panic.
	if got := remoteIP(&net.UnixAddr{Name: "/tmp/sock", Net: "unix"}); got != nil {
		t.Errorf("remoteIP(unix) = %v, want nil", got)
	}
}
