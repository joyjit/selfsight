// Package web embeds the built React dashboard so the whole UI ships inside the
// single selfsight binary (DESIGN.md, principle 4 "One artifact").
//
// The embedded tree is web/dist, produced by `npm run build` in this directory.
// A committed dist/.gitkeep ensures `go build` works before the web app is
// built; in that state the binary simply has no UI to serve. The Dockerfile and
// CI build the web app first so a real dashboard is embedded.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Assets returns the built dashboard rooted at dist/, or false if no real build
// is embedded (only the .gitkeep placeholder is present).
func Assets() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return sub, false
	}
	return sub, true
}
