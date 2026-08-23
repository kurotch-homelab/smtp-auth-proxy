// Package webui serves the admin single-page application that `npm run build`
// writes into dist/. The directory is committed with only a .gitkeep so that a
// plain `go build` works before the UI has been built; in that case Available
// reports false and the handler returns a short explanatory page instead of a
// confusing 404.
package webui

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

const (
	// indexFile is the SPA entrypoint; unmatched routes fall back to it so that
	// client-side routing survives a hard refresh.
	indexFile = "index.html"
	// assetPrefix holds content-hashed bundles emitted by Vite.
	assetPrefix = "assets/"
)

// FS returns the built admin UI rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		// Unreachable: dist/ is embedded above, so Sub cannot fail.
		panic(err)
	}
	return sub
}

// Available reports whether a built UI is embedded in this binary.
func Available() bool {
	return hasIndex(FS())
}

func hasIndex(root fs.FS) bool {
	_, err := fs.Stat(root, indexFile)
	return err == nil
}

// Handler serves the SPA. Requests under /api are never handled here; mount
// this as the router's trailing fallback.
func Handler() http.Handler {
	return handlerFor(FS())
}

func handlerFor(root fs.FS) http.Handler {
	if !hasIndex(root) {
		return http.HandlerFunc(notBuilt)
	}
	files := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		// index.html always goes through serveIndex so it is served with
		// Cache-Control: no-store, whether it was requested directly or reached
		// as the SPA fallback.
		if name == "" || name == indexFile {
			serveIndex(w, r, root)
			return
		}

		if _, err := fs.Stat(root, name); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			// A stale client asking for a hashed bundle that no longer exists must
			// get a 404, never HTML it would try to execute as JavaScript.
			if strings.HasPrefix(name, assetPrefix) {
				http.NotFound(w, r)
				return
			}
			serveIndex(w, r, root)
			return
		}

		files.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, root fs.FS) {
	b, err := fs.ReadFile(root, indexFile)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// index.html names hashed assets, so it must never be cached.
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(b)
}

func notBuilt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("admin UI was not built into this binary; run 'make web-build' and rebuild\n"))
}
