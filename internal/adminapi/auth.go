package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/logsafe"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// oidcStateCookie carries a pending single sign-on across the redirect.
const oidcStateCookie = "sap_oidc_state"

// authConfigResponse tells the sign-in page what it may offer.
type authConfigResponse struct {
	LocalEnabled bool `json:"localEnabled"`
	OIDCEnabled  bool `json:"oidcEnabled"`
	// OIDCLabel is what to put on the single sign-on button.
	OIDCLabel string `json:"oidcLabel,omitempty"`
}

func (s *Server) handleAuthConfig(w http.ResponseWriter, _ *http.Request) {
	resp := authConfigResponse{
		LocalEnabled: s.local != nil,
		OIDCEnabled:  s.oidc != nil,
	}
	if resp.OIDCEnabled {
		resp.OIDCLabel = "Single sign-on"
	}
	writeJSON(w, http.StatusOK, resp)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// sessionResponse is returned after a successful sign-in and from /me.
type sessionResponse struct {
	User        userResponse           `json:"user"`
	Permissions []adminauth.Permission `json:"permissions"`
	// CSRFToken must be echoed in the X-CSRF-Token header on every mutating
	// request.
	CSRFToken string    `json:"csrfToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.local == nil {
		writeError(w, http.StatusForbidden, CodeForbidden, "password sign-in is disabled")
		return
	}

	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		writeValidationError(w, map[string]string{
			"username": "required",
			"password": "required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user, err := s.local.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		s.recordFailedSignIn(ctx, r, req.Username, err)

		switch {
		case errors.Is(err, adminauth.ErrLockedOut):
			// Worth distinguishing: the user needs to know to wait rather than
			// keep guessing, and reaching this already required the right
			// username.
			writeError(w, http.StatusTooManyRequests, CodeForbidden,
				"too many failed attempts; try again later")
		case errors.Is(err, adminauth.ErrLocalDisabled):
			writeError(w, http.StatusForbidden, CodeForbidden, "password sign-in is disabled")
		case errors.Is(err, adminauth.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "incorrect username or password")
		default:
			s.writeStoreError(w, r, err)
		}
		return
	}

	s.completeSignIn(w, r, user, "password")
}

// completeSignIn issues a session and returns it.
func (s *Server) completeSignIn(w http.ResponseWriter, r *http.Request, user *store.AdminUser, method string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	issued, err := s.sessions.Issue(ctx, user, r)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor:      user,
		Action:     "auth.sign_in",
		TargetType: "user",
		TargetID:   user.ID,
		TargetName: user.Username,
		Details:    map[string]any{"method": method},
	})

	http.SetCookie(w, s.sessions.Cookie(issued.Token, issued.Session.ExpiresAt))
	writeJSON(w, http.StatusOK, sessionResponse{
		User:        toUserResponse(user),
		Permissions: adminauth.PermissionsFor(user.Role),
		CSRFToken:   issued.CSRFToken,
		ExpiresAt:   issued.Session.ExpiresAt,
	})
}

// recordFailedSignIn writes an audit entry for a refused attempt.
//
// The username is recorded because that is the useful part when reviewing an
// attack; the password never is.
func (s *Server) recordFailedSignIn(ctx context.Context, r *http.Request, username string, cause error) {
	s.audit(ctx, r, auditEntry{
		Action:     "auth.sign_in",
		TargetType: "user",
		TargetName: username,
		Result:     store.ResultFailure,
		Details:    map[string]any{"reason": cause.Error()},
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.sessions.Revoke(ctx, auth.Session.ID); err != nil {
		s.logger(r).Warn("could not revoke a session on sign-out", "reason", err)
	}
	s.audit(ctx, r, auditEntry{
		Actor:      auth.User,
		Action:     "auth.sign_out",
		TargetType: "user",
		TargetID:   auth.User.ID,
		TargetName: auth.User.Username,
	})

	http.SetCookie(w, s.sessions.ClearCookie())
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())

	writeJSON(w, http.StatusOK, sessionResponse{
		User:        toUserResponse(auth.User),
		Permissions: adminauth.PermissionsFor(auth.User.Role),
		CSRFToken:   auth.Session.CSRFToken,
		ExpiresAt:   auth.Session.ExpiresAt,
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// minPasswordLength is a floor, not a policy. Composition rules push people
// towards predictable substitutions; length is what actually helps.
const minPasswordLength = 12

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())

	if s.local == nil {
		writeError(w, http.StatusForbidden, CodeForbidden, "password sign-in is disabled")
		return
	}
	if auth.User.Source != store.SourceLocal {
		writeError(w, http.StatusForbidden, CodeForbidden,
			"this account signs in through the identity provider; change the password there")
		return
	}

	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.NewPassword) < minPasswordLength {
		writeValidationError(w, map[string]string{
			"newPassword": "must be at least 12 characters",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Re-check the current password: a session left open on a shared machine
	// should not be enough to lock its owner out of their own account.
	if _, err := s.local.Authenticate(ctx, auth.User.Username, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "the current password is incorrect")
		return
	}

	if err := s.local.SetPassword(ctx, auth.User, req.NewPassword); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor:      auth.User,
		Action:     "user.change_password",
		TargetType: "user",
		TargetID:   auth.User.ID,
		TargetName: auth.User.Username,
	})

	// SetPassword revoked every session, this one included, so the browser has
	// to sign in again.
	http.SetCookie(w, s.sessions.ClearCookie())
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "single sign-on is not configured")
		return
	}

	req, err := s.oidc.Start()
	if err != nil {
		s.logger(r).Error("could not start single sign-on", "reason", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "something went wrong")
		return
	}

	// The pending request travels in a short-lived cookie rather than server
	// state, so the callback need not land on the replica that started it.
	encoded, err := json.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "something went wrong")
		return
	}
	http.SetCookie(w, adminauth.StateCookie(oidcStateCookie, encodeState(encoded), s.cookieSecure))

	http.Redirect(w, r, req.URL, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "single sign-on is not configured")
		return
	}

	if errCode := r.URL.Query().Get("error"); errCode != "" {
		s.logger(r).Warn("the identity provider refused a sign-in",
			"error", logsafe.String(errCode),
			"description", logsafe.String(r.URL.Query().Get("error_description")))
		s.redirectToSignIn(w, r, "sso_failed")
		return
	}

	cookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		s.redirectToSignIn(w, r, "sso_expired")
		return
	}
	// One use only: clear it before the exchange so a replayed callback finds
	// nothing.
	http.SetCookie(w, expiredStateCookie(s.cookieSecure))

	var pending adminauth.AuthRequest
	decoded, err := decodeState(cookie.Value)
	if err != nil || json.Unmarshal(decoded, &pending) != nil {
		s.redirectToSignIn(w, r, "sso_expired")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user, err := s.oidc.Complete(ctx, r.URL.Query().Get("code"), pending,
		r.URL.Query().Get("state"), s.oidcClient)
	if err != nil {
		s.logger(r).Warn("single sign-on did not complete", "reason", logsafe.Error(err))
		s.recordFailedSignIn(ctx, r, "(single sign-on)", err)

		switch {
		case errors.Is(err, adminauth.ErrNoRole):
			s.redirectToSignIn(w, r, "sso_no_role")
		case errors.Is(err, adminauth.ErrSignupDisabled):
			s.redirectToSignIn(w, r, "sso_unknown_user")
		default:
			s.redirectToSignIn(w, r, "sso_failed")
		}
		return
	}

	issued, err := s.sessions.Issue(ctx, user, r)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	s.audit(ctx, r, auditEntry{
		Actor:      user,
		Action:     "auth.sign_in",
		TargetType: "user",
		TargetID:   user.ID,
		TargetName: user.Username,
		Details:    map[string]any{"method": "oidc"},
	})

	http.SetCookie(w, s.sessions.Cookie(issued.Token, issued.Session.ExpiresAt))
	// The browser arrived here by a top-level navigation, so it has to be sent
	// somewhere it can render rather than handed JSON.
	http.Redirect(w, r, "/", http.StatusFound)
}

// redirectToSignIn sends the browser back to the sign-in page with a reason the
// UI can turn into a message.
func (s *Server) redirectToSignIn(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/login?error="+reason, http.StatusFound)
}

// session cookie; see the note in adminauth.
//
//nolint:gosec // G124: Secure is configurable for the same reason as the
func expiredStateCookie(secure bool) *http.Cookie {
	c := adminauth.StateCookie(oidcStateCookie, "", secure)
	c.MaxAge = -1
	return c
}
