package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"selfsight/internal/core"
	"selfsight/internal/device"
)

// The event log is each device's diary — what the config history can't tell:
// whether the AP answered, what it reported about itself changing, and edits
// to our own inventory entry for it. One append-only text file per device
// under <dataDir>/events/, plus one fleet-wide file (<dataDir>/events.log,
// deliberately outside events/ so it can't collide with a device's file) for
// events that belong to no single device. Lines are "<RFC3339>\t<message>".
//
// Like the config-history store, these files map the operator's network
// (addresses, serials) and must never leave the box.

const (
	eventLogMaxBytes  = 256 << 10 // per-file size that triggers a trim
	eventLogKeepLines = 1000      // lines kept when trimming
	eventTailLines    = 200       // lines the events endpoint serves
)

func (s *Server) deviceEventPath(name string) string {
	base := s.dataDir
	if base == "" {
		base = "data"
	}
	return filepath.Join(base, "events", name+".log")
}

func (s *Server) fleetEventPath() string {
	base := s.dataDir
	if base == "" {
		base = "data"
	}
	return filepath.Join(base, "events.log")
}

func (s *Server) logDeviceEvent(name, format string, args ...any) {
	s.appendEvent(s.deviceEventPath(name), fmt.Sprintf(format, args...))
}

func (s *Server) logFleetEvent(format string, args ...any) {
	s.appendEvent(s.fleetEventPath(), fmt.Sprintf(format, args...))
}

// appendEvent writes one timestamped line, best-effort: the log is a diary,
// never worth failing the operation that produced the event.
func (s *Server) appendEvent(path, msg string) {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("event log %s: %v", path, err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("event log %s: %v", path, err)
		return
	}
	_, werr := f.WriteString(time.Now().UTC().Format(time.RFC3339) + "\t" + msg + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		log.Printf("event log %s: %v %v", path, werr, cerr)
		return
	}
	trimEventLog(path)
}

// trimEventLog keeps the file bounded: once it outgrows the threshold, only
// the newest lines survive. Called with eventMu held.
func trimEventLog(path string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= eventLogMaxBytes {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) > eventLogKeepLines {
		lines = lines[len(lines)-eventLogKeepLines:]
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// noteReach records the outcome of contacting a device and logs one line per
// reachability flip — never one per poll. The first contact after startup is
// only logged when it fails; answering is the normal case and stays silent.
// A device that answered "Insight-managed" still answered.
func (s *Server) noteReach(dev *core.Device, err error) {
	ok := err == nil || errors.Is(err, device.ErrManaged)
	s.eventStateMu.Lock()
	prev, known := s.reach[dev.Name]
	s.reach[dev.Name] = ok
	s.eventStateMu.Unlock()
	switch {
	case !ok && (!known || prev):
		s.logDeviceEvent(dev.Name, "no answer at %s: %v", dev.Host, err)
	case ok && known && !prev:
		s.logDeviceEvent(dev.Name, "answering again at %s", dev.Host)
	}
}

// identityFields is what a reading says about WHO the device is — the fields
// worth a diary line when they change. Live counters (clients, uptime,
// traffic) are deliberately absent: they change every poll and mean nothing.
func identityFields(st *device.Status) map[string]string {
	if st == nil || st.System == nil {
		return nil
	}
	sys := st.System
	return map[string]string{
		"name": sys.Name, "serial": sys.Serial, "mac": sys.MAC,
		"firmware": sys.Firmware, "ip": sys.IP, "gateway": sys.Gateway,
	}
}

// identityOrder fixes the log order of identity fields so diffs read stably.
var identityOrder = []string{"name", "serial", "mac", "firmware", "ip", "gateway"}

// logIdentityChanges compares what the AP now reports about itself against
// the previous reading and logs every identifying field that differs — e.g.
// the address it believes it has, or a different serial answering at the same
// host (a swapped unit). Empty values don't compare: a partial read must not
// fake a change.
func (s *Server) logIdentityChanges(name string, prev, cur *device.Status) {
	was, now := identityFields(prev), identityFields(cur)
	if was == nil || now == nil {
		return
	}
	for _, k := range identityOrder {
		if was[k] != "" && now[k] != "" && was[k] != now[k] {
			s.logDeviceEvent(name, "it now reports %s %s (was %s)", k, now[k], was[k])
		}
	}
}

// rememberConfigFile records the config file as the server itself last loaded
// or wrote it, so checkConfigFile can tell a foreign edit from our own.
func (s *Server) rememberConfigFile() {
	if s.cfgPath == "" {
		return
	}
	sum, err := fileSHA256(s.cfgPath)
	if err != nil {
		return
	}
	s.eventStateMu.Lock()
	s.cfgSeen = sum
	s.eventStateMu.Unlock()
}

// checkConfigFile logs when the config file on disk no longer matches what the
// server last loaded or wrote — someone edited it behind the dashboard's back.
// It only records the fact (once per edit); loading the change stays a
// deliberate act via reload.
func (s *Server) checkConfigFile() {
	if s.cfgPath == "" {
		return
	}
	sum, err := fileSHA256(s.cfgPath)
	if err != nil {
		return
	}
	s.eventStateMu.Lock()
	seen := s.cfgSeen
	changed := seen != "" && sum != seen
	s.cfgSeen = sum
	s.eventStateMu.Unlock()
	if changed {
		s.logFleetEvent("%s changed on disk, not via the dashboard (reload to pick it up)", filepath.Base(s.cfgPath))
	}
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// eventView is one log line over the wire.
type eventView struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// handleDeviceEvents serves the tail of a device's event log, oldest first.
// An empty list — not an error — when nothing has ever been logged.
func (s *Server) handleDeviceEvents(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	events := []eventView{}
	if b, err := os.ReadFile(s.deviceEventPath(dev.Name)); err == nil {
		lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if len(lines) > eventTailLines {
			lines = lines[len(lines)-eventTailLines:]
		}
		for _, ln := range lines {
			ts, msg, found := strings.Cut(ln, "\t")
			if !found {
				continue
			}
			events = append(events, eventView{Time: ts, Message: msg})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": dev.Name, "events": events})
}
