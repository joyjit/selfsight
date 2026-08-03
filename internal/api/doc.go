// Package api holds the net/http handlers that expose selfsight's REST API.
//
// API first: every feature is a documented REST endpoint before it has UI
// (DESIGN.md, principle 3). The React app in web/ is a client of this API and
// is embedded into the binary at build time.
package api
