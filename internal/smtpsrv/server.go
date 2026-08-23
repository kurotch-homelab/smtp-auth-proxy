package smtpsrv

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/config"
)

// Options configure the SMTP front end.
type Options struct {
	// Hostname is announced in the EHLO banner and used in Received headers.
	Hostname  string
	Listeners []config.Listener
	TLSConfig *tls.Config

	MaxMessageBytes     int64
	MaxRecipients       int
	MaxConnections      int
	MaxConnectionsPerIP int
	MaxAuthFailures     int

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// AuthTimeout bounds one credential check, and SubmitTimeout one enqueue.
	AuthTimeout   time.Duration
	SubmitTimeout time.Duration

	// AllowInsecureAuth advertises AUTH on unencrypted connections. Only for
	// devices with no TLS support at all.
	AllowInsecureAuth bool
	// RecordSubjects stores message subjects, which may contain personal data.
	RecordSubjects bool

	// ProxyProtocol accepts a PROXY header from the listed networks, so a TCP
	// load balancer can pass through the real client address.
	ProxyProtocol config.ProxyProtocol

	Auth      Authenticator
	Submitter Submitter
	// Recorder receives metrics; nil disables them.
	Recorder Recorder
	Log      *slog.Logger
}

// Server runs one or more SMTP listeners over a shared backend.
type Server struct {
	hostname          string
	allowInsecureAuth bool
	requireTLS        bool
	recordSubjects    bool

	maxMessageBytes int64
	maxRecipients   int
	maxAuthFailures int

	authTimeout   time.Duration
	submitTimeout time.Duration

	auth          Authenticator
	submitter     Submitter
	recorder      Recorder
	log           *slog.Logger
	limiter       *connLimiter
	proxyProtocol config.ProxyProtocol

	// listeners pairs each configured socket with its go-smtp server.
	listeners []*listener

	// mu guards the bound sockets and the shutdown flag. Addresses() and
	// Shutdown() can be called from another goroutine — a readiness probe, a
	// signal handler — while Serve is still binding.
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	shutdown bool

	// ready is closed once every listener is bound, so callers can wait for a
	// usable server instead of polling for an address.
	ready     chan struct{}
	readyOnce sync.Once
}

type listener struct {
	cfg    config.Listener
	server *smtp.Server
	// net is written by Serve and read by Addresses and Shutdown; take
	// Server.mu for both.
	net net.Listener
}

// timeout defaults, used when Options leaves them at zero.
const (
	defaultAuthTimeout   = 10 * time.Second
	defaultSubmitTimeout = 30 * time.Second
	// gracePeriod is how long in-flight sessions have to finish once Serve's
	// context is canceled.
	gracePeriod = 30 * time.Second
)

// New builds a Server from Options without binding anything yet.
func New(opts Options) (*Server, error) {
	if opts.Auth == nil {
		return nil, errors.New("smtpsrv: an Authenticator is required")
	}
	if opts.Submitter == nil {
		return nil, errors.New("smtpsrv: a Submitter is required")
	}
	if len(opts.Listeners) == 0 {
		return nil, errors.New("smtpsrv: at least one listener is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Recorder == nil {
		opts.Recorder = nopRecorder{}
	}

	requireTLS := false
	for _, l := range opts.Listeners {
		if l.RequireTLS {
			requireTLS = true
		}
		if l.TLS != config.TLSNone && opts.TLSConfig == nil {
			return nil, fmt.Errorf("smtpsrv: listener %s uses TLS but no certificate was provided", l.Address)
		}
	}

	s := &Server{
		hostname:          opts.Hostname,
		allowInsecureAuth: opts.AllowInsecureAuth,
		requireTLS:        requireTLS,
		recordSubjects:    opts.RecordSubjects,
		maxMessageBytes:   opts.MaxMessageBytes,
		maxRecipients:     opts.MaxRecipients,
		maxAuthFailures:   opts.MaxAuthFailures,
		authTimeout:       orDefault(opts.AuthTimeout, defaultAuthTimeout),
		submitTimeout:     orDefault(opts.SubmitTimeout, defaultSubmitTimeout),
		auth:              opts.Auth,
		submitter:         opts.Submitter,
		recorder:          opts.Recorder,
		log:               opts.Log,
		limiter:           newConnLimiter(opts.MaxConnectionsPerIP, opts.MaxConnections),
		proxyProtocol:     opts.ProxyProtocol,
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.ready = make(chan struct{})

	for _, cfg := range opts.Listeners {
		s.listeners = append(s.listeners, &listener{cfg: cfg, server: s.newSMTPServer(cfg, opts)})
	}
	return s, nil
}

func (s *Server) newSMTPServer(cfg config.Listener, opts Options) *smtp.Server {
	srv := smtp.NewServer(&backend{server: s})
	srv.Addr = cfg.Address
	srv.Domain = opts.Hostname
	srv.MaxMessageBytes = opts.MaxMessageBytes
	srv.MaxRecipients = opts.MaxRecipients
	srv.ReadTimeout = opts.ReadTimeout
	srv.WriteTimeout = opts.WriteTimeout
	srv.AllowInsecureAuth = opts.AllowInsecureAuth
	srv.ErrorLog = smtpLogger{log: opts.Log, addr: cfg.Address}

	if cfg.TLS != config.TLSNone {
		srv.TLSConfig = opts.TLSConfig
	}
	return srv
}

// baseContext is canceled when the server shuts down, so in-flight
// authentication and submission stop rather than hanging on a closing process.
func (s *Server) baseContext() context.Context { return s.ctx }

// Serve binds every listener and blocks until they stop.
//
// When ctx is canceled the listeners are shut down gracefully, so a caller can
// drive the whole lifecycle from one context rather than pairing Serve with a
// separate Shutdown. It returns the first error that is not a normal shutdown,
// after every listener has been closed.
func (s *Server) Serve(ctx context.Context) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)

	// A cancellation while serving triggers a graceful shutdown.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gracePeriod)
			defer cancel()
			_ = s.Shutdown(shutdownCtx)
		case <-stopped:
		}
	}()

	for _, l := range s.listeners {
		netListener, err := s.bind(l)
		if err != nil {
			// Close whatever is already up, so a partial start does not leave
			// the process listening on some ports but not others. The caller's
			// context may already be canceled, which must not prevent the
			// cleanup from running.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gracePeriod)
			_ = s.Shutdown(cleanupCtx)
			cancel()
			s.markReady()
			return err
		}
		s.mu.Lock()
		l.net = netListener
		s.mu.Unlock()
	}
	s.markReady()

	for _, l := range s.listeners {
		wg.Add(1)
		go func() {
			defer wg.Done()

			s.mu.Lock()
			bound := l.net
			s.mu.Unlock()
			if bound == nil {
				return
			}

			s.log.Info("smtp listener started",
				"address", bound.Addr().String(), "tls", l.cfg.TLS, "require_tls", l.cfg.RequireTLS)

			if err := l.server.Serve(bound); err != nil && !isClosedErr(err) {
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("smtpsrv: listener %s: %w", l.cfg.Address, err)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return first
}

// Ready returns a channel closed once every listener is bound, or once Serve
// has given up trying.
func (s *Server) Ready() <-chan struct{} { return s.ready }

func (s *Server) markReady() { s.readyOnce.Do(func() { close(s.ready) }) }

func (s *Server) bind(l *listener) (net.Listener, error) {
	var (
		netListener net.Listener
		err         error
	)

	var lc net.ListenConfig
	netListener, err = lc.Listen(s.ctx, "tcp", l.cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("smtpsrv: binding %s: %w", l.cfg.Address, err)
	}

	// The connection gate has to run on the raw socket: a PROXY header arrives
	// in the clear, before any TLS handshake.
	wrapped, err := s.wrapListener(netListener)
	if err != nil {
		_ = netListener.Close()
		return nil, err
	}

	if l.cfg.TLS == config.TLSImplicit {
		// Implicit TLS — submission on port 465 — where the client speaks TLS
		// from the first byte.
		//
		// TLS goes on the outside so that go-smtp receives a *tls.Conn it can
		// recognize: it type-asserts the connection directly, and a wrapper in
		// between would make it treat an encrypted connection as plaintext and
		// refuse AUTH.
		wrapped = tls.NewListener(wrapped, l.server.TLSConfig)
	}
	return wrapped, nil
}

// wrapListener applies the connection limiter and, when configured, PROXY
// protocol support.
func (s *Server) wrapListener(inner net.Listener) (net.Listener, error) {
	gate := &gateListener{inner: inner, limiter: s.limiter, log: s.log}

	if s.proxyProtocol.Enabled {
		handshake, err := newProxyHandshake(s.proxyProtocol.TrustedNetworks)
		if err != nil {
			return nil, err
		}
		gate.proxy = handshake
	}
	return gate, nil
}

// Shutdown stops accepting connections and waits for in-flight sessions.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	s.mu.Unlock()

	s.cancel()
	// A caller that shuts down before Serve finished binding would otherwise
	// wait on Ready forever.
	s.markReady()

	var firstErr error
	for _, l := range s.listeners {
		s.mu.Lock()
		bound := l.net
		s.mu.Unlock()
		if bound == nil {
			continue
		}
		if err := l.server.Shutdown(ctx); err != nil && firstErr == nil && !isClosedErr(err) {
			firstErr = err
		}
	}
	return firstErr
}

// Addresses reports what each listener actually bound to, which matters when a
// test asks for port 0.
func (s *Server) Addresses() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]string, 0, len(s.listeners))
	for _, l := range s.listeners {
		if l.net != nil {
			out = append(out, l.net.Addr().String())
		}
	}
	return out
}

// backend creates one session per connection.
type backend struct{ server *Server }

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{
		server: b.server,
		conn:   c,
		remote: c.Conn().RemoteAddr(),
	}, nil
}

// gateListener enforces the connection caps and, when configured, reads the
// PROXY header — both before any SMTP is spoken.
//
// Per-connection failures are handled here rather than returned: go-smtp's
// accept loop backs off exponentially on a temporary error, so one client
// sending a bad PROXY header would slow every other client down.
type gateListener struct {
	inner   net.Listener
	limiter *connLimiter
	proxy   *proxyHandshake
	log     *slog.Logger
}

func (l *gateListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		if !l.limiter.acquire(conn.RemoteAddr()) {
			total, _ := l.limiter.counts()
			l.log.Warn("refusing a connection over the limit",
				"remote", addrKey(conn.RemoteAddr()), "open", total)
			// Closing without a greeting is deliberate: a client at its limit
			// should back off, and writing a 421 first would cost another
			// round trip for every attempt.
			_ = conn.Close()
			continue
		}

		gated := &limitedConn{Conn: conn, limiter: l.limiter}
		if l.proxy == nil {
			return gated, nil
		}

		wrapped, err := l.proxy.accept(gated)
		if err != nil {
			l.log.Warn("rejecting a connection during the PROXY handshake",
				"remote", addrKey(conn.RemoteAddr()), "reason", err)
			_ = gated.Close()
			continue
		}
		return wrapped, nil
	}
}

func (l *gateListener) Close() error   { return l.inner.Close() }
func (l *gateListener) Addr() net.Addr { return l.inner.Addr() }

// limitedConn releases its slot exactly once, however the connection ends.
type limitedConn struct {
	net.Conn
	limiter *connLimiter
	once    sync.Once
}

func (c *limitedConn) Close() error {
	c.once.Do(func() { c.limiter.release(c.RemoteAddr()) })
	return c.Conn.Close()
}

// smtpLogger adapts slog to the interface go-smtp expects.
type smtpLogger struct {
	log  *slog.Logger
	addr string
}

func (l smtpLogger) Printf(format string, v ...any) {
	l.log.Warn("smtp server error", "listener", l.addr, "detail", fmt.Sprintf(format, v...))
}

func (l smtpLogger) Println(v ...any) {
	l.log.Warn("smtp server error", "listener", l.addr, "detail", fmt.Sprint(v...))
}

func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, smtp.ErrServerClosed)
}

func orDefault(v, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return v
}
