package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"selfsight/internal/core"
	"selfsight/internal/device"
)

// This file is the write side of the inventory: adding, editing, and removing a
// device edits config.yaml on disk (via core's node-surgery helpers) and swaps
// the new config in live, so the whole "adopt and manage an AP" loop works from
// the dashboard without hand-editing YAML. All of it requires the server to
// know where its config file is (started with --config); without that these
// endpoints answer 501, since there is nothing to write.

// deviceInput is the wire shape for adding or updating a device. Kept separate
// from core.Device so the JSON API doesn't depend on the YAML tags, and so the
// UI sends clean lowercase field names.
type deviceInput struct {
	Name     string        `json:"name"`
	Host     string        `json:"host"`
	Model    string        `json:"model"`
	Serial   string        `json:"serial"`
	Username string        `json:"username"`
	Password string        `json:"password"`
	Desired  *desiredInput `json:"desired"`
}

type desiredInput struct {
	SSIDs  []ssidInput           `json:"ssids"`
	Radios map[string]radioInput `json:"radios"`
}

type ssidInput struct {
	Name       string `json:"name"`
	VLAN       int    `json:"vlan"`
	Security   string `json:"security"`
	Passphrase string `json:"passphrase"`
	Hidden     *bool  `json:"hidden,omitempty"`  // tri-state: absent = not managed
	Enabled    *bool  `json:"enabled,omitempty"` // tri-state: absent = not managed
	// HasPassphrase is response-only: it tells the edit form that a passphrase
	// is stored, so it can offer "leave blank to keep" without the value ever
	// being sent to the browser. Ignored on input.
	HasPassphrase bool `json:"hasPassphrase,omitempty"`
}

type radioInput struct {
	Channel string `json:"channel"`
	Power   string `json:"power"`
	Enabled *bool  `json:"enabled,omitempty"` // tri-state: absent = not managed
}

func (in deviceInput) toDevice() core.Device {
	d := core.Device{
		Name:     in.Name,
		Host:     in.Host,
		Model:    in.Model,
		Serial:   in.Serial,
		Username: in.Username,
		Password: in.Password,
	}
	if in.Desired != nil {
		for _, s := range in.Desired.SSIDs {
			d.Desired.SSIDs = append(d.Desired.SSIDs, core.SSID{
				Name: s.Name, VLAN: s.VLAN, Security: s.Security, Passphrase: s.Passphrase,
				Hidden: s.Hidden, Enabled: s.Enabled,
			})
		}
		if len(in.Desired.Radios) > 0 {
			d.Desired.Radios = map[string]core.Radio{}
			for k, r := range in.Desired.Radios {
				d.Desired.Radios[k] = core.Radio{Channel: r.Channel, Power: r.Power, Enabled: r.Enabled}
			}
		}
	}
	return d
}

// writeEnabled reports whether config writes are possible (the server knows its
// config path). If not, it answers 501 and returns false.
func (s *Server) writeEnabled(w http.ResponseWriter) bool {
	if s.cfgPath == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "config editing is not enabled (server was started without a config path)",
		})
		return false
	}
	return true
}

// editStatus maps a core edit error to an HTTP status. A duplicate name is a
// conflict, an unknown device a 404; everything else (validation, I/O) is a 400.
func editStatus(err error) int {
	switch {
	case errors.Is(err, core.ErrDeviceExists):
		return http.StatusConflict
	case errors.Is(err, core.ErrNoSuchDevice):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}

func (s *Server) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	if !s.writeEnabled(w) {
		return
	}
	var in deviceInput
	if err := decodeJSONBody(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	cfg, err := core.AddDevice(s.cfgPath, in.toDevice())
	if err != nil {
		writeJSON(w, editStatus(err), map[string]string{"error": err.Error()})
		return
	}
	s.swapConfig(cfg)
	s.logDeviceEvent(in.Name, "added to the inventory with address %s (dashboard)", in.Host)
	writeJSON(w, http.StatusCreated, map[string]any{"device": in.Name, "devices": len(cfg.Devices)})
}

// handleDeviceConfig returns a device's full declared config so the edit form
// can prefill from it — everything except the secrets, which never leave the
// process. Neither the device password nor any declared WiFi passphrase is
// sent; each is reported only as "there is one stored" (hasPassword,
// hasPassphrase). An edit that leaves either field blank keeps the current
// value (see handleUpdateDevice and core.UpdateDevice).
func (s *Server) handleDeviceConfig(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	in := deviceInput{Name: dev.Name, Host: dev.Host, Model: dev.Model, Serial: dev.Serial, Username: dev.Username}
	if len(dev.Desired.SSIDs) > 0 || len(dev.Desired.Radios) > 0 {
		d := &desiredInput{Radios: map[string]radioInput{}}
		for _, s := range dev.Desired.SSIDs {
			d.SSIDs = append(d.SSIDs, ssidInput{
				Name: s.Name, VLAN: s.VLAN, Security: s.Security,
				Hidden: s.Hidden, Enabled: s.Enabled,
				HasPassphrase: s.Passphrase != "",
			})
		}
		for k, radio := range dev.Desired.Radios {
			d.Radios[k] = radioInput{Channel: radio.Channel, Power: radio.Power, Enabled: radio.Enabled}
		}
		in.Desired = d
	}
	// hasPassword lets the form show "leave blank to keep" only when there is
	// one to keep — without ever sending the value.
	writeJSON(w, http.StatusOK, map[string]any{"device": in, "hasPassword": dev.Password != ""})
}

func (s *Server) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	if !s.writeEnabled(w) {
		return
	}
	name := r.PathValue("name")
	if s.deviceBusy(w, name) {
		return
	}
	var in deviceInput
	if err := decodeJSONBody(w, r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if in.Name == "" {
		in.Name = name // a body that omits the name keeps the existing one
	}
	dev := in.toDevice()
	// The pre-edit entry, for the event log: what actually changed is only
	// knowable by comparing against it.
	var oldHost string
	if old := s.device(name); old != nil {
		oldHost = old.Host
	}
	// An edit that leaves the password or serial blank keeps the current one —
	// blank means "unchanged", not "clear". The preserve happens in
	// core.UpdateDevice against the RAW file value, never the loaded config:
	// preserving from the runtime config would materialize an env-expanded
	// `${VAR}` secret into the file.
	cfg, err := core.UpdateDevice(s.cfgPath, name, dev)
	if err != nil {
		writeJSON(w, editStatus(err), map[string]string{"error": err.Error()})
		return
	}
	// A rename moves the device's backup history with it — otherwise the old
	// archives are orphaned and restore can't see them. Best-effort: the config
	// edit is already committed, so a move failure is logged, not surfaced.
	if dev.Name != name {
		oldDir, newDir := s.deviceDataDir(name), s.deviceDataDir(dev.Name)
		if _, err := os.Stat(oldDir); err == nil {
			if _, err := os.Stat(newDir); err == nil {
				log.Printf("rename %s -> %s: both backup dirs exist, leaving %s in place", name, dev.Name, oldDir)
			} else if err := os.Rename(oldDir, newDir); err != nil {
				log.Printf("rename %s -> %s: move backups: %v", name, dev.Name, err)
			}
		}
		// The cached last reading follows the device too (same-name collisions
		// can't happen here: UpdateDevice already refused a duplicate name).
		if _, err := os.Stat(s.deviceStatusPath(name)); err == nil {
			if err := os.Rename(s.deviceStatusPath(name), s.deviceStatusPath(dev.Name)); err != nil {
				log.Printf("rename %s -> %s: move status cache: %v", name, dev.Name, err)
			}
		}
		// And its event log — the diary belongs to the device, not the name.
		if _, err := os.Stat(s.deviceEventPath(name)); err == nil {
			if err := os.Rename(s.deviceEventPath(name), s.deviceEventPath(dev.Name)); err != nil {
				log.Printf("rename %s -> %s: move event log: %v", name, dev.Name, err)
			}
		}
	}
	s.swapConfig(cfg)
	if dev.Name != name {
		s.logDeviceEvent(dev.Name, "renamed from %s (dashboard)", name)
	}
	if oldHost != "" && oldHost != dev.Host {
		s.logDeviceEvent(dev.Name, "address changed %s -> %s (dashboard)", oldHost, dev.Host)
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": in.Name})
}

func (s *Server) handleRemoveDevice(w http.ResponseWriter, r *http.Request) {
	if !s.writeEnabled(w) {
		return
	}
	name := r.PathValue("name")
	if s.deviceBusy(w, name) {
		return
	}
	cfg, err := core.RemoveDevice(s.cfgPath, name)
	if err != nil {
		writeJSON(w, editStatus(err), map[string]string{"error": err.Error()})
		return
	}
	s.swapConfig(cfg)
	s.logDeviceEvent(name, "removed from the inventory (dashboard)")
	writeJSON(w, http.StatusOK, map[string]any{"removed": name, "devices": len(cfg.Devices)})
}

// handleTestConnection logs into an AP with credentials the user just typed and
// reports what it found, so the add-device form can confirm reachability and
// credentials before the device is committed to config. It does not touch the
// config file. The device need not be in the inventory; the session it warms is
// keyed by host, so a later add reuses it instead of burning another login slot.
func (s *Server) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	var in deviceInput
	if err := decodeJSONBody(w, r, &in); err != nil || in.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must include a host"})
		return
	}
	// This is the one endpoint that dials an address the caller supplies
	// directly, so the address is held to the same rules as a configured one:
	// a plain IP or host name with an optional port, nothing else.
	if err := core.ValidateHost(in.Host); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	mgr := s.newManager(in.Host, in.Username, in.Password)
	st, err := mgr.Status(ctx)
	if err != nil {
		// Reachable-but-managed is a distinct, actionable outcome.
		code := http.StatusBadGateway
		if errors.Is(err, device.ErrManaged) {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	out := map[string]any{"ok": true, "host": in.Host}
	if st.System != nil {
		out["name"] = st.System.Name
		out["serial"] = st.System.Serial
		out["firmware"] = st.System.Firmware
		out["standalone"] = st.System.Standalone
		out["model"] = in.Model
	}
	writeJSON(w, http.StatusOK, out)
}
