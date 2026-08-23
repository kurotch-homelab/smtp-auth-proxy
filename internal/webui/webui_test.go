package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// builtFS stands in for a real `npm run build` output.
func builtFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte("<!doctype html><title>app</title>")},
		"assets/main-abc123.js": {Data: []byte("console.log(1)")},
		"favicon.svg":           {Data: []byte("<svg/>")},
	}
}

func TestAvailableReportsPlaceholderDist(t *testing.T) {
	t.Parallel()

	// The committed dist/ holds only .gitkeep, so an unbuilt tree must report
	// false rather than serving a broken page.
	if Available() {
		t.Skip("a built UI is embedded in this binary; nothing to assert")
	}

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if body := rec.Body.String(); body == "" {
		t.Error("unbuilt handler should explain what to do, got empty body")
	}
}

func TestHandlerRoutes(t *testing.T) {
	t.Parallel()

	h := handlerFor(builtFS())

	tests := []struct {
		name         string
		method       string
		target       string
		wantStatus   int
		wantBodyPart string
		wantNoStore  bool
	}{
		{
			name:         "root serves index.html",
			method:       http.MethodGet,
			target:       "/",
			wantStatus:   http.StatusOK,
			wantBodyPart: "<title>app</title>",
			wantNoStore:  true,
		},
		{
			name:         "existing asset is served verbatim",
			method:       http.MethodGet,
			target:       "/assets/main-abc123.js",
			wantStatus:   http.StatusOK,
			wantBodyPart: "console.log(1)",
		},
		{
			name:         "client-side route falls back to index.html",
			method:       http.MethodGet,
			target:       "/queue/42",
			wantStatus:   http.StatusOK,
			wantBodyPart: "<title>app</title>",
			wantNoStore:  true,
		},
		{
			// A stale client asking for a hashed bundle that no longer exists
			// must get a 404, never HTML it would try to execute as JavaScript.
			name:       "missing hashed asset 404s instead of falling back",
			method:     http.MethodGet,
			target:     "/assets/main-deadbeef.js",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "HEAD on a fallback route returns no body",
			method:     http.MethodHead,
			target:     "/dashboard",
			wantStatus: http.StatusOK,
		},
		{
			// Path traversal must not escape the embedded filesystem.
			name:         "traversal is cleaned and falls back",
			method:       http.MethodGet,
			target:       "/../../etc/passwd",
			wantStatus:   http.StatusOK,
			wantBodyPart: "<title>app</title>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, http.NoBody))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantBodyPart != "" && !strings.Contains(rec.Body.String(), tt.wantBodyPart) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBodyPart)
			}
			if tt.method == http.MethodHead && rec.Body.Len() != 0 {
				t.Errorf("HEAD returned a body of %d bytes", rec.Body.Len())
			}
			if tt.wantNoStore && rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
		})
	}
}
