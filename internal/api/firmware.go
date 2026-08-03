package api

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"selfsight/internal/device"
)

// upgradeState is the observable progress of one device's firmware upgrade,
// polled by the dashboard while the upgrade goroutine runs.
type upgradeState struct {
	mu      sync.Mutex
	Running bool                   `json:"running"`
	Phase   string                 `json:"phase,omitempty"`
	Percent int                    `json:"percent,omitempty"`
	Err     string                 `json:"error,omitempty"`
	Outcome *device.UpgradeOutcome `json:"outcome,omitempty"`
}

func (u *upgradeState) view() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := map[string]any{"running": u.Running}
	if u.Phase != "" {
		out["phase"], out["percent"] = u.Phase, u.Percent
	}
	if u.Err != "" {
		out["error"] = u.Err
	}
	if u.Outcome != nil {
		out["outcome"] = u.Outcome
	}
	return out
}

// upgradeFor returns (creating if needed) a device's upgrade state.
func (s *Server) upgradeFor(name string) *upgradeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upgrades == nil {
		s.upgrades = map[string]*upgradeState{}
	}
	if u := s.upgrades[name]; u != nil {
		return u
	}
	u := &upgradeState{}
	s.upgrades[name] = u
	return u
}

// upgradeInProgress reports whether ANY device is mid-upgrade. Firmware
// upgrades run strictly one AP at a time across the whole fleet — flashing two
// APs at once risks taking down the network that carries the upgrade itself.
//
// This is for reporting only (the progress endpoint). Deciding whether an
// upgrade may start must go through claimUpgrade: a separate check and act
// leaves a window in which two requests both see an idle fleet.
func (s *Server) upgradeInProgress() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runningUpgradeLocked()
}

// runningUpgradeLocked names the device currently upgrading. Caller holds s.mu.
func (s *Server) runningUpgradeLocked() (string, bool) {
	for name, u := range s.upgrades {
		u.mu.Lock()
		running := u.Running
		u.mu.Unlock()
		if running {
			return name, true
		}
	}
	return "", false
}

// claimUpgrade atomically reserves the fleet's single upgrade slot for name.
// It answers the "is anything running?" question and marks this device as
// running under one hold of s.mu, so two concurrent requests cannot both be
// told the fleet is idle. Returns the device already upgrading and false when
// the slot is taken.
//
// The claim must be released with releaseUpgrade if the upgrade does not go
// on to start — otherwise the slot stays held for the process's lifetime.
func (s *Server) claimUpgrade(name string) (*upgradeState, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if busy, running := s.runningUpgradeLocked(); running {
		return nil, busy, false
	}
	if s.upgrades == nil {
		s.upgrades = map[string]*upgradeState{}
	}
	u := s.upgrades[name]
	if u == nil {
		u = &upgradeState{}
		s.upgrades[name] = u
	}
	u.mu.Lock()
	u.Running, u.Phase, u.Percent, u.Err, u.Outcome = true, "starting", 0, "", nil
	u.mu.Unlock()
	return u, "", true
}

// releaseUpgrade gives the slot back when a claimed upgrade never started.
func releaseUpgrade(u *upgradeState) {
	u.mu.Lock()
	u.Running, u.Phase = false, ""
	u.mu.Unlock()
}

// deviceBusy answers 503 (with progress detail) when the device is mid-
// firmware-upgrade — its manager lock is held for the whole flash, so any
// other operation would silently hang for minutes instead.
func (s *Server) deviceBusy(w http.ResponseWriter, name string) bool {
	u := s.upgradeFor(name)
	u.mu.Lock()
	running := u.Running
	u.mu.Unlock()
	if !running {
		return false
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error": "firmware upgrade in progress on " + name, "progress": u.view(),
	})
	return true
}

// handleFirmwareCheck asks the AP to query the vendor cloud for a newer image
// and returns the result. Deliberate action (it contacts NETGEAR's servers
// from the AP); selfsight never does this on its own.
func (s *Server) handleFirmwareCheck(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()
	fw, err := dm.mgr.CheckFirmware(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name})
		return
	}
	writeJSON(w, http.StatusOK, fw)
}

// handleFirmwareUpgrade starts a firmware upgrade in the background and
// returns immediately; progress is polled via the progress endpoint. THIS
// REBOOTS THE AP and drops every client; an interrupted flash can brick the
// device. Refused while any device in the fleet is already upgrading.
func (s *Server) handleFirmwareUpgrade(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	// Take the fleet's single upgrade slot first, in one atomic step. The
	// serial check below talks to the AP over the network; doing it before the
	// claim would leave a window of whole round-trips in which a second request
	// also sees an idle fleet and starts flashing a different device.
	u, busy, claimed := s.claimUpgrade(dev.Name)
	if !claimed {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "an upgrade is already running on " + busy + " — firmware upgrades are strictly one AP at a time",
		})
		return
	}
	{
		// Confirm we're flashing the recorded unit before anything starts.
		dm := s.managerFor(dev)
		dm.mu.Lock()
		ok := s.checkSerial(r.Context(), w, dev, dm.mgr)
		dm.mu.Unlock()
		if !ok {
			releaseUpgrade(u) // nothing started — hand the slot back
			return
		}
	}

	dm := s.managerFor(dev)
	backupDir := s.deviceDataDir(dev.Name)
	go func() {
		// Detached from the HTTP request: the upgrade outlives it by minutes.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		dm.mu.Lock()
		defer dm.mu.Unlock()
		outcome, err := dm.mgr.Upgrade(ctx, backupDir, func(p device.UpgradeProgress) {
			u.mu.Lock()
			u.Phase, u.Percent = p.Phase, p.Percent
			u.mu.Unlock()
		})
		if outcome != nil && outcome.Backup != "" {
			path, berr := s.finishBackup(dev, outcome.Backup, time.Now())
			outcome.Backup = path
			if berr != nil {
				log.Printf("backup post-process %s: %v", dev.Name, berr)
			}
		}
		u.mu.Lock()
		u.Running = false
		u.Outcome = outcome
		if err != nil {
			u.Err = err.Error()
		}
		u.mu.Unlock()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"device": dev.Name, "started": true})
}

func (s *Server) handleFirmwareProgress(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	writeJSON(w, http.StatusOK, s.upgradeFor(dev.Name).view())
}
