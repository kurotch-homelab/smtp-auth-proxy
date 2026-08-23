package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/adminauth"
	appcrypto "github.com/kurotch-homelab/smtp-auth-proxy/internal/crypto"
	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// userResponse is an admin user as the API returns it.
//
// There is deliberately no password field in either direction: a hash is not
// something a client should ever see, and a password is only ever set through
// the dedicated endpoints.
type userResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email,omitempty"`
	DisplayName string     `json:"displayName,omitempty"`
	Role        store.Role `json:"role"`
	Source      string     `json:"source"`
	Disabled    bool       `json:"disabled"`
	// HasPassword lets the UI show whether password sign-in works for this
	// account without revealing anything about the password itself.
	HasPassword bool       `json:"hasPassword"`
	LockedUntil *time.Time `json:"lockedUntil,omitempty"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

func toUserResponse(u *store.AdminUser) userResponse {
	resp := userResponse{
		ID: u.ID, Username: u.Username, Email: u.Email, DisplayName: u.DisplayName,
		Role: u.Role, Source: u.Source, Disabled: u.Disabled,
		HasPassword: u.PasswordHash.Valid && u.PasswordHash.String != "",
		CreatedAt:   u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
	if u.LockedUntil.Valid {
		resp.LockedUntil = &u.LockedUntil.Time
	}
	if u.LastLoginAt.Valid {
		resp.LastLoginAt = &u.LastLoginAt.Time
	}
	return resp
}

func (s *Server) mountUsers(r chi.Router) {
	r.Route("/users", func(ur chi.Router) {
		ur.With(s.require(adminauth.PermManageUsers)).Get("/", s.handleListUsers)
		ur.With(s.require(adminauth.PermManageUsers)).Post("/", s.handleCreateUser)
		ur.With(s.require(adminauth.PermManageUsers)).Get("/{id}", s.handleGetUser)
		ur.With(s.require(adminauth.PermManageUsers)).Patch("/{id}", s.handleUpdateUser)
		ur.With(s.require(adminauth.PermManageUsers)).Delete("/{id}", s.handleDeleteUser)
		ur.With(s.require(adminauth.PermManageUsers)).Post("/{id}/password", s.handleSetUserPassword)
	})
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	users, err := s.db.Users().List(ctx)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	items := make([]userResponse, 0, len(users))
	for _, u := range users {
		items = append(items, toUserResponse(u))
	}
	writeJSON(w, http.StatusOK, listResponse[userResponse]{Items: items, Total: int64(len(items))})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user, err := s.db.Users().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

type createUserRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Password    string `json:"password"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	fields := map[string]string{}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		fields["username"] = "required"
	}
	role, err := adminauth.ParseRole(req.Role)
	if err != nil {
		fields["role"] = "must be admin, operator or viewer"
	}
	if len(req.Password) < minPasswordLength {
		fields["password"] = "must be at least 12 characters"
	}
	if len(fields) > 0 {
		writeValidationError(w, fields)
		return
	}

	hash, err := appcrypto.HashPassword(req.Password)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user := &store.AdminUser{
		Username:     username,
		Email:        strings.TrimSpace(req.Email),
		DisplayName:  strings.TrimSpace(req.DisplayName),
		PasswordHash: store.NullString(hash),
		Role:         role,
		Source:       store.SourceLocal,
	}
	if err := s.db.Users().Create(ctx, user); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: authFrom(r.Context()).User, Action: "user.create",
		TargetType: "user", TargetID: user.ID, TargetName: user.Username,
		Details: map[string]any{"role": string(role), "password": req.Password},
	})

	writeJSON(w, http.StatusCreated, toUserResponse(user))
}

type updateUserRequest struct {
	Email       *string `json:"email"`
	DisplayName *string `json:"displayName"`
	Role        *string `json:"role"`
	Disabled    *bool   `json:"disabled"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	var req updateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user, err := s.db.Users().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	previousRole := user.Role
	changes := map[string]any{}

	if req.Email != nil {
		user.Email = strings.TrimSpace(*req.Email)
		changes["email"] = user.Email
	}
	if req.DisplayName != nil {
		user.DisplayName = strings.TrimSpace(*req.DisplayName)
		changes["displayName"] = user.DisplayName
	}
	if req.Role != nil {
		role, err := adminauth.ParseRole(*req.Role)
		if err != nil {
			writeValidationError(w, map[string]string{"role": "must be admin, operator or viewer"})
			return
		}
		user.Role = role
		changes["role"] = string(role)
	}
	if req.Disabled != nil {
		user.Disabled = *req.Disabled
		changes["disabled"] = user.Disabled
	}

	// Removing or disabling the last administrator would lock everyone out of
	// their own proxy, with no way back in short of editing the database.
	if losingAdmin(user, previousRole) {
		if err := s.requireAnotherAdmin(ctx, user.ID); err != nil {
			writeError(w, http.StatusConflict, CodeConflict, err.Error())
			return
		}
	}

	if err := s.db.Users().Update(ctx, user); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	// A demotion or a disable has to take effect now, not whenever they next
	// sign out.
	if user.Role != previousRole || user.Disabled {
		if err := s.sessions.RevokeAllForUser(ctx, user.ID); err != nil {
			s.logger(r).Warn("could not revoke sessions after a user change",
				"username", user.Username, "reason", err)
		}
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "user.update",
		TargetType: "user", TargetID: user.ID, TargetName: user.Username,
		Details: changes,
	})

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User
	id := chi.URLParam(r, "id")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user, err := s.db.Users().Get(ctx, id)
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if user.ID == actor.ID {
		// Deleting your own account mid-session is almost always a mistake, and
		// there is no undo.
		writeError(w, http.StatusConflict, CodeConflict, "you cannot delete your own account")
		return
	}
	if user.Role == store.RoleAdmin && !user.Disabled {
		if err := s.requireAnotherAdmin(ctx, user.ID); err != nil {
			writeError(w, http.StatusConflict, CodeConflict, err.Error())
			return
		}
	}

	if err := s.db.Users().Delete(ctx, id); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "user.delete",
		TargetType: "user", TargetID: user.ID, TargetName: user.Username,
	})
	writeJSON(w, http.StatusNoContent, nil)
}

type setPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	actor := authFrom(r.Context()).User

	if s.local == nil {
		writeError(w, http.StatusForbidden, CodeForbidden, "password sign-in is disabled")
		return
	}

	var req setPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Password) < minPasswordLength {
		writeValidationError(w, map[string]string{"password": "must be at least 12 characters"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	user, err := s.db.Users().Get(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.writeStoreError(w, r, err)
		return
	}
	if user.Source != store.SourceLocal {
		writeError(w, http.StatusConflict, CodeConflict,
			"this account signs in through the identity provider and has no password here")
		return
	}

	if err := s.local.SetPassword(ctx, user, req.Password); err != nil {
		s.writeStoreError(w, r, err)
		return
	}

	s.audit(ctx, r, auditEntry{
		Actor: actor, Action: "user.set_password",
		TargetType: "user", TargetID: user.ID, TargetName: user.Username,
	})
	writeJSON(w, http.StatusNoContent, nil)
}

// losingAdmin reports whether a change takes administrator rights away.
func losingAdmin(user *store.AdminUser, previousRole store.Role) bool {
	if previousRole != store.RoleAdmin {
		return false
	}
	return user.Role != store.RoleAdmin || user.Disabled
}

// requireAnotherAdmin fails unless somebody else can still administer the proxy.
func (s *Server) requireAnotherAdmin(ctx context.Context, excludingID string) error {
	users, err := s.db.Users().List(ctx)
	if err != nil {
		return errors.New("could not check whether another administrator remains")
	}
	for _, u := range users {
		if u.ID != excludingID && u.Role == store.RoleAdmin && !u.Disabled {
			return nil
		}
	}
	return errors.New("this is the only administrator; promote someone else first")
}
