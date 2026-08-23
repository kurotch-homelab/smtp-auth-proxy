package adminapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/logsafe"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// contextKey is unexported so nothing outside this package can plant a value
// the handlers would read as an authenticated session.
type contextKey int

const (
	authContextKey contextKey = iota
	requestIDKey
)

// authFrom returns the session on a request, or nil.
func authFrom(ctx context.Context) *store.Authenticated {
	auth, _ := ctx.Value(authContextKey).(*store.Authenticated)
	return auth
}

// requestIDFrom returns the request's correlation identifier.
func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// logger returns a logger tagged with the request's identity.
//
// The username originated as user input, so it is neutralized here once rather
// than at every call site that inherits it.
func (s *Server) logger(r *http.Request) *slog.Logger {
	log := s.log.With("request_id", requestIDFrom(r.Context()))
	if auth := authFrom(r.Context()); auth != nil {
		log = log.With("actor", logsafe.String(auth.User.Username))
	}
	return log
}

// withRequestID tags each request so a log line and an error response can be
// tied together.
func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := store.NewID()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// recoverPanics turns a handler panic into a 500 instead of a dropped
// connection, and logs the stack.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			// A client that goes away mid-response makes the writer panic with
			// ErrAbortHandler; that is not a bug worth a stack trace.
			if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(p)
			}
			s.logger(r).Error("a request handler panicked",
				"path", logsafe.String(r.URL.Path), "method", logsafe.String(r.Method),
				"panic", logsafe.String(fmt.Sprint(p)), "stack", string(debug.Stack()))
			writeError(w, http.StatusInternalServerError, CodeInternal, "something went wrong")
		}()
		next.ServeHTTP(w, r)
	})
}

// logRequests records each API call.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		if rec.status >= http.StatusInternalServerError {
			level = slog.LevelError
		} else if rec.status >= http.StatusBadRequest {
			level = slog.LevelWarn
		}

		s.logger(r).Log(r.Context(), level, "admin api request",
			"method", logsafe.String(r.Method),
			"path", logsafe.String(r.URL.Path),
			"status", rec.status,
			"duration", time.Since(start),
			"remote", adminauth.ClientIP(r, s.trustedProxies),
		)
	})
}

// statusRecorder remembers the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
	// wrote guards against a handler calling WriteHeader twice.
	wrote bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

// requireSession rejects anything without a valid session, and enforces CSRF on
// state-changing requests.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := s.sessions.Authenticate(r.Context(), r)
		if err != nil {
			if errors.Is(err, adminauth.ErrNoSession) {
				writeError(w, http.StatusUnauthorized, CodeUnauthorized, "sign in to continue")
				return
			}
			s.writeStoreError(w, r, err)
			return
		}

		if err := s.sessions.CheckCSRF(auth, r); err != nil {
			s.logger(r).Warn("rejected a request that failed its CSRF check",
				"path", logsafe.String(r.URL.Path), "method", logsafe.String(r.Method),
				"remote", adminauth.ClientIP(r, s.trustedProxies))
			writeError(w, http.StatusForbidden, CodeCSRF,
				"this request could not be verified; reload the page and try again")
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey, auth)))
	})
}

// require builds middleware that enforces a permission.
//
// Every route states what it needs. A route with no such wrapper is reachable
// by any signed-in user, which is why the authorization test walks the router
// and fails on a route it does not recognize.
func (s *Server) require(perm adminauth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := authFrom(r.Context())
			if auth == nil {
				writeError(w, http.StatusUnauthorized, CodeUnauthorized, "sign in to continue")
				return
			}
			if !adminauth.Can(auth.User.Role, perm) {
				s.logger(r).Warn("refused an action the role does not allow",
					"path", logsafe.String(r.URL.Path), "method", logsafe.String(r.Method),
					"role", auth.User.Role, "permission", perm)
				writeError(w, http.StatusForbidden, CodeForbidden,
					"your role does not allow this")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// noCache stops a browser or an intermediary from holding on to API responses.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets the defensive headers that apply to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The admin UI is a self-contained bundle: nothing it needs comes from
		// another origin, so the policy can be strict.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
