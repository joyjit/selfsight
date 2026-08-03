package api

import (
	"context"
	"net/http"

	"selfsight/internal/core"
	"selfsight/internal/device"
)

// configRadioKeys is the config file's fixed radio vocabulary; whether the
// device actually has a band is the driver's call.
var configRadioKeys = map[string]bool{"2g": true, "5g": true, "6g": true}

// radioWidths is the accepted channel-width vocabulary (MHz); the driver maps
// these to the AP's numeric codes. Only the widths whose codes are captured
// and used are listed.
var radioWidths = map[string]bool{"20": true, "40": true}

// handleDeviceChange applies a single one-off change straight to the device —
// nothing is recorded in config.yaml. This is the dashboard acting as a remote
// control: the AP stays the only source of truth, exactly as if the change had
// been made on the AP's own page, but through the guarded pipeline (busy +
// serial checks, fresh backup, read-back verify).
//
// A field that IS declared in the device's desired config is refused: the next
// apply would silently revert the one-off, so the two must not fight — change
// the declaration instead, or remove it.
func (s *Server) handleDeviceChange(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if s.deviceBusy(w, dev.Name) {
		return
	}

	var body struct {
		SSID *struct {
			Name       string `json:"name"`
			Hidden     *bool  `json:"hidden"`
			Enabled    *bool  `json:"enabled"`
			Passphrase string `json:"passphrase"`
			VLAN       *int   `json:"vlan"`
			Security   string `json:"security"`
		} `json:"ssid"`
		Radio *struct {
			Band    string `json:"band"` // config radio key: 2g, 5g, 6g
			Channel string `json:"channel"`
			Width   string `json:"width"` // channel width in MHz: "20"/"40"/"80"
			Enabled *bool  `json:"enabled"`
		} `json:"radio"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil || (body.SSID == nil) == (body.Radio == nil) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "body must set exactly one of \"ssid\" or \"radio\"",
		})
		return
	}

	dm := s.managerFor(dev)

	var run func(ctx context.Context, backupDir string) (*device.ApplyResult, error)
	switch {
	case body.SSID != nil:
		in := body.SSID
		if in.Name == "" || (in.Hidden == nil && in.Enabled == nil && in.Passphrase == "" && in.VLAN == nil && in.Security == "") {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "ssid change needs \"name\" and at least one of \"hidden\"/\"enabled\"/\"passphrase\"/\"vlan\"/\"security\"",
			})
			return
		}
		// WPA preshared keys are 8–63 printable ASCII characters by spec; the
		// AP silently misbehaves outside that, so refuse up front.
		if in.Passphrase != "" && (len(in.Passphrase) < 8 || len(in.Passphrase) > 63) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "passphrase must be 8–63 characters",
			})
			return
		}
		vlan := 0
		if in.VLAN != nil {
			if *in.VLAN < 1 || *in.VLAN > 4094 {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "vlan must be 1–4094",
				})
				return
			}
			vlan = *in.VLAN
		}
		if in.Security != "" {
			if err := dm.mgr.ValidateSecurity(in.Security); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		}
		if msg := declaredSSIDField(dev, in.Name, in.Hidden != nil, in.Enabled != nil,
			in.Passphrase != "", in.VLAN != nil, in.Security != ""); msg != "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": msg})
			return
		}
		want := core.SSID{
			Name: in.Name, Hidden: in.Hidden, Enabled: in.Enabled,
			Passphrase: in.Passphrase, VLAN: vlan, Security: in.Security,
		}
		run = func(ctx context.Context, dir string) (*device.ApplyResult, error) {
			return dm.mgr.ApplySSID(ctx, dir, want)
		}
	case body.Radio != nil:
		in := body.Radio
		if !configRadioKeys[in.Band] || (in.Channel == "" && in.Width == "" && in.Enabled == nil) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "radio change needs \"band\" (2g/5g/6g) and at least one of \"channel\"/\"width\"/\"enabled\"",
			})
			return
		}
		if in.Width != "" && !radioWidths[in.Width] {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "width must be 20 or 40 (MHz)",
			})
			return
		}
		if msg := declaredRadioField(dev, in.Band, in.Channel != "", in.Enabled != nil); msg != "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": msg})
			return
		}
		bands := map[string]core.Radio{
			in.Band: {Channel: in.Channel, Width: in.Width, Enabled: in.Enabled},
		}
		run = func(ctx context.Context, dir string) (*device.ApplyResult, error) {
			return dm.mgr.ApplyRadios(ctx, dir, bands)
		}
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !s.checkSerial(r.Context(), w, dev, dm.mgr) {
		return
	}
	res, err := run(r.Context(), s.deviceDataDir(dev.Name))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "device": dev.Name})
		return
	}
	s.finishApplyBackup(dev, res)
	s.snapshotAfterApply(r.Context(), dev, dm, []*device.ApplyResult{res})
	code := http.StatusOK
	if !res.Applied {
		code = http.StatusConflict // wrote, but the read-back did not confirm it
	}
	// Same shape as apply's response so the dashboard renders both the same way.
	writeJSON(w, code, map[string]any{
		"device": dev.Name, "results": []*device.ApplyResult{res}, "skipped": []string{},
	})
}

// declaredSSIDField reports (as a ready error message) whether the fields being
// changed are declared for this SSID in the device's desired config.
func declaredSSIDField(dev *core.Device, name string, hidden, enabled, passphrase, vlan, security bool) string {
	for _, d := range dev.Desired.SSIDs {
		if d.Name != name {
			continue
		}
		if (hidden && d.Hidden != nil) || (enabled && d.Enabled != nil) || (passphrase && d.Passphrase != "") ||
			(vlan && d.VLAN != 0) || (security && d.Security != "") {
			return "ssid " + name + " has this setting declared in config.yaml — a one-off change would be reverted by the next apply; change or remove the declaration instead"
		}
	}
	return ""
}

// declaredRadioField is declaredSSIDField for a radio band's channel/enabled.
func declaredRadioField(dev *core.Device, band string, channel, enabled bool) string {
	r, ok := dev.Desired.Radios[band]
	if !ok {
		return ""
	}
	if (channel && r.Channel != "" && r.Channel != "auto") || (enabled && r.Enabled != nil) {
		return "radio " + band + " has this setting declared in config.yaml — a one-off change would be reverted by the next apply; change or remove the declaration instead"
	}
	return ""
}
