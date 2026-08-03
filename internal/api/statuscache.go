package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"selfsight/internal/device"
)

// The status cache is the last successful reading from each AP, kept on disk
// so the dashboard can paint instantly (and across restarts) while a fresh
// read happens behind it. It is a display cache only — never a source of
// truth, never compared against anything: the AP itself is the master copy
// of its config, and every contact with the AP overwrites the cache.

// cachedStatus is the on-disk and over-the-wire envelope: the reading plus
// when it was taken, so the UI can say how old the picture is.
type cachedStatus struct {
	FetchedAt time.Time      `json:"fetchedAt"`
	Status    *device.Status `json:"status"`
}

// deviceStatusPath is where a device's last reading lives:
// <dataDir>/status/<device>.json.
func (s *Server) deviceStatusPath(name string) string {
	base := s.dataDir
	if base == "" {
		base = "data"
	}
	return filepath.Join(base, "status", name+".json")
}

// saveStatusCache persists a successful reading. Best-effort: the cache is a
// convenience, so a write failure is logged, never surfaced to the request
// that produced the reading.
func (s *Server) saveStatusCache(name string, st *device.Status) {
	path := s.deviceStatusPath(name)
	// The previous reading is about to be overwritten — this is the one moment
	// a change in what the AP reports about itself can be noticed, so it goes
	// to the device's event log before it's gone (task: per-device event log).
	if b, err := os.ReadFile(path); err == nil {
		var prev cachedStatus
		if json.Unmarshal(b, &prev) == nil {
			s.logIdentityChanges(name, prev.Status, st)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("status cache %s: %v", name, err)
		return
	}
	data, err := json.Marshal(cachedStatus{FetchedAt: time.Now().UTC(), Status: st})
	if err != nil {
		log.Printf("status cache %s: %v", name, err)
		return
	}
	// Write-then-rename so a crash mid-write can't leave a torn file behind.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("status cache %s: %v", name, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("status cache %s: %v", name, err)
	}
}

// handleDeviceStatusCached serves the saved last reading without contacting
// the AP. 404 when the device has never been read successfully.
func (s *Server) handleDeviceStatusCached(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	data, err := os.ReadFile(s.deviceStatusPath(dev.Name))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no cached reading for " + dev.Name + " yet"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
