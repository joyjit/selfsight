package api

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"selfsight/internal/core"
	"selfsight/internal/device"
)

// handleDeviceApply pushes a device's declared config onto the device — the
// drift "Apply" action. Only out-of-sync declared fields are written, each
// through the guarded pipeline (fresh backup → write → read-back verify).
// Wireless writes bounce the radio, briefly dropping that AP's clients; the
// per-device lock is held throughout so nothing else touches the device, and
// fleet-wide applies are the caller's job to serialize (the dashboard only
// ever applies one device at a time).
func (s *Server) handleDeviceApply(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if !s.beginWrite(w, dev.Name) {
		return
	}
	defer s.releaseFleetWrite(dev.Name)

	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	status, err := dm.mgr.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name})
		return
	}
	if !serialMatches(w, dev, status) {
		return
	}
	ssids := withPassphraseMatch(r.Context(), dm.mgr, dev.Desired, observedSSIDs(status))
	report := core.ComputeDrift(dev.Desired, ssids, observedRadios(status))
	changes, skipped := planChanges(dev.Desired, report)
	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"device": dev.Name, "inSync": report.InSync, "results": []any{}, "skipped": skipped,
		})
		return
	}

	// Strictly sequential; each change takes its own fresh backup. One failed
	// change stops the run — the device may be mid-transition and the human
	// should look before more writes pile on. That covers both kinds of
	// failure: the write erroring outright, and the write going through but
	// the read-back not confirming it (res.Applied false), which is just as
	// much a reason to stop.
	results := make([]*device.ApplyResult, 0, len(changes))
	for _, ch := range changes {
		res, err := ch.run(r.Context(), dm.mgr, s.deviceDataDir(dev.Name))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": err.Error(), "device": dev.Name, "change": ch.describe, "results": results,
			})
			return
		}
		s.finishApplyBackup(dev, res)
		results = append(results, res)
		if !res.Applied {
			break
		}
	}
	s.snapshotAfterApply(r.Context(), dev, dm, results)
	code := http.StatusOK
	for _, res := range results {
		if !res.Applied {
			code = http.StatusConflict // a write the read-back did not confirm
		}
	}
	writeJSON(w, code, map[string]any{"device": dev.Name, "results": results, "skipped": skipped})
}

// handleDeleteSSID removes a wireless network from the device — the one
// imperative write that has no declarative form (an SSID absent from desired
// config is unmanaged, not deleted). It goes through the same guarded pipeline
// as every write: busy + serial checks, fresh backup, then read-back verify
// that the SSID is gone. The device refuses its primary network, as does any
// SSID still in the declared config — the next apply would just recreate it.
func (s *Server) handleDeleteSSID(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if !s.beginWrite(w, dev.Name) {
		return
	}
	defer s.releaseFleetWrite(dev.Name)

	ssid := r.PathValue("ssid")
	for _, d := range dev.Desired.SSIDs {
		if d.Name == ssid {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "ssid " + ssid + " is declared in this device's desired config — remove it there first, or the next apply would recreate it",
			})
			return
		}
	}

	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !s.checkSerial(r.Context(), w, dev, dm.mgr) {
		return
	}
	res, err := dm.mgr.DeleteSSID(r.Context(), s.deviceDataDir(dev.Name), ssid)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name})
		return
	}
	s.finishApplyBackup(dev, res)
	s.snapshotAfterApply(r.Context(), dev, dm, []*device.ApplyResult{res})
	code := http.StatusOK
	if !res.Applied {
		code = http.StatusConflict // wrote, but read-back still shows the SSID
	}
	writeJSON(w, code, res)
}

// plannedChange is one vendor-neutral write the drift plan wants to make,
// expressed against the device.Driver contract — no protocol vocabulary here.
type plannedChange struct {
	describe string
	run      func(ctx context.Context, drv device.Driver, backupDir string) (*device.ApplyResult, error)
}

// planChanges turns a drift report into driver operations. Radio drifts
// (channel, on/off) collapse into one combined call (every radio write
// bounces the radios — once is enough); each drifting SSID becomes its own
// call. Items that cannot be applied are reported in skipped rather than
// silently dropped.
func planChanges(d core.Desired, report core.DriftReport) (changes []plannedChange, skipped []string) {
	radios := map[string]core.Radio{}
	ssidNames := map[string]bool{}
	for _, it := range report.Items {
		if it.InSync {
			continue
		}
		switch {
		case strings.HasPrefix(it.Scope, "radio:"):
			key := strings.TrimPrefix(it.Scope, "radio:")
			switch it.Field {
			case "channel":
				r := radios[key]
				r.Channel = it.Desired
				radios[key] = r
			case "enabled":
				r := radios[key]
				on := it.Desired == "on"
				r.Enabled = &on
				radios[key] = r
			default:
				skipped = append(skipped, it.Scope+" "+it.Field+": not applyable")
			}
		case strings.HasPrefix(it.Scope, "ssid:"):
			ssidNames[strings.TrimPrefix(it.Scope, "ssid:")] = true
		default:
			skipped = append(skipped, it.Scope+" "+it.Field+": not applyable")
		}
	}

	names := make([]string, 0, len(ssidNames))
	for n := range ssidNames {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		var want *core.SSID
		for i := range d.SSIDs {
			if d.SSIDs[i].Name == name {
				want = &d.SSIDs[i]
			}
		}
		if want == nil {
			skipped = append(skipped, "ssid:"+name+": not in desired config")
			continue
		}
		w := *want
		changes = append(changes, plannedChange{
			describe: "apply ssid " + w.Name,
			run: func(ctx context.Context, drv device.Driver, dir string) (*device.ApplyResult, error) {
				return drv.ApplySSID(ctx, dir, w)
			},
		})
	}
	if len(radios) > 0 {
		changes = append(changes, plannedChange{
			describe: "apply radio settings",
			run: func(ctx context.Context, drv device.Driver, dir string) (*device.ApplyResult, error) {
				return drv.ApplyRadios(ctx, dir, radios)
			},
		})
	}
	return changes, skipped
}
