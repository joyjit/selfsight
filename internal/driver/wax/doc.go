// Package wax is the driver for NETGEAR WAX-series access points: session
// management, reads (system, clients, radios), and later the guarded write
// path (backup -> diff -> write -> re-read -> verify).
//
// Every behavior this package depends on is backed by a sanitized transcript
// under testdata/wax610/. No code here is written against an imagined API;
// see DESIGN.md, "Capture first". Implementation is gated on those fixtures.
package wax
