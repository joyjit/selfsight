package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// staticHandler serves the embedded dashboard. Unknown non-asset paths fall
// back to index.html so client-side routing works. If no UI was embedded (a
// bare `go build` with only the dist placeholder), it serves a short message
// pointing at the API and the build step.
func (s *Server) staticHandler() http.Handler {
	if s.ui == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("selfsight: no dashboard embedded in this build.\n" +
				"Build it with `npm --prefix web run build`, or use the API directly at /api/devices.\n"))
		})
	}

	fileServer := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve real files as-is; otherwise fall back to index.html.
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.ui, p); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}
