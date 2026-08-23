package adminapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/kurotch-homelab/smtp-auth-proxy/internal/store"
)

// APIError is the body returned for every failure.
//
// One shape for every error means the UI has one thing to handle, and the
// machine-readable code means it can react to a specific case without matching
// on prose.
type APIError struct {
	// Code is a stable identifier such as "not_found" or "conflict".
	Code string `json:"code"`
	// Message is safe to show a user and never contains anything secret.
	Message string `json:"message"`
	// Fields carries per-field validation messages, keyed by field name.
	Fields map[string]string `json:"fields,omitempty"`
}

// Error codes. These are part of the API contract; the UI matches on them.
const (
	CodeBadRequest   = "bad_request"
	CodeValidation   = "validation_failed"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeReferenced   = "still_referenced"
	CodeImmutable    = "managed_externally"
	CodeCSRF         = "csrf_failed"
	CodeInternal     = "internal_error"
)

// writeJSON sends a value as the response body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The admin API returns data about mail; nothing here should be cached by a
	// browser or an intermediary.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status line is already sent, so there is nothing to do but note it.
		slog.Default().Warn("could not write a JSON response", "reason", err)
	}
}

// writeError sends an error body.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, APIError{Code: code, Message: message})
}

// writeValidationError sends per-field messages.
func writeValidationError(w http.ResponseWriter, fields map[string]string) {
	writeJSON(w, http.StatusUnprocessableEntity, APIError{
		Code:    CodeValidation,
		Message: "some fields are not valid",
		Fields:  fields,
	})
}

// writeStoreError maps a repository error onto a response.
//
// Anything unrecognized becomes a 500 with a generic message: an unexpected
// database error can carry table names, constraint names and occasionally
// values, none of which belong in an API response.
func (s *Server) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, CodeConflict, "that name is already in use")
	case errors.Is(err, store.ErrReferenced):
		writeError(w, http.StatusConflict, CodeReferenced,
			"something else still refers to this; remove that first")
	case errors.Is(err, store.ErrImmutable):
		writeError(w, http.StatusConflict, CodeImmutable,
			"this object is declared in the bootstrap file and cannot be edited here")
	default:
		s.logger(r).Error("unhandled error", "path", r.URL.Path, "reason", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "something went wrong")
	}
}

// decodeJSON reads a request body into v, rejecting anything unexpected.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	// A request body is attacker-controlled; cap it so a stray large upload
	// cannot exhaust memory.
	const maxBody = 1 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	dec := json.NewDecoder(r.Body)
	// Unknown fields are rejected so a client sending "enable" instead of
	// "enabled" hears about it rather than silently changing nothing.
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "the request body could not be read: "+err.Error())
		return false
	}
	return true
}
