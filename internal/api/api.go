package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"selfsight/internal/backup"
	"selfsight/internal/core"
	"selfsight/internal/device"
	"selfsight/internal/discovery"
	"selfsight/internal/driver/wax"
)

// Server holds what the HTTP handlers need: the loaded config, the embedded UI,
// and one warm-session manager per device (created lazily, reused across
// requests so we don't burn the AP's limited login slots).
type Server struct {
	ui      fs.FS  // embedded dashboard, or nil if none was built in
	dataDir string // where device config backups are written
	cfgPath string // config file for on-demand reload ("" = reload disabled)
	mux     *http.ServeMux

	cfgMu sync.RWMutex
	cfg   *core.Config

	auth authState

	mu       sync.Mutex
	managers map[string]*deviceManager
	upgrades map[string]*upgradeState

	// Event-log state (eventlog.go): eventMu serializes log-file writes;
	// eventStateMu guards the in-memory last-known facts the log lines are
	// derived from — per-device reachability and the config file as this
	// server last saw it.
	eventMu      sync.Mutex
	eventStateMu sync.Mutex
	reach        map[string]bool
	cfgSeen      string

	// history is the local git store of config snapshots (nil if it could not
	// be opened — history is best-effort and never blocks a backup).
	history *backup.HistoryStore

	// codec is the vendor's backup-archive format and crypto (device.Codec);
	// handlers never touch vendor crypto directly.
	codec device.Codec
}

// ServeHTTP makes Server an http.Handler. Every request passes the auth gate
// first (a no-op unless server.auth is configured).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	s.mux.ServeHTTP(w, r)
}

// config returns the current config snapshot. Handlers work on the snapshot so
// a concurrent reload can't swap the inventory out from under them mid-request.
func (s *Server) config() *core.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// EnableReload allows POST /api/config/reload to re-read the config from path.
func (s *Server) EnableReload(path string) {
	s.cfgPath = path
	// Baseline for the out-of-band edit check: this is the file as loaded.
	s.rememberConfigFile()
}

// deviceManager guards one AP's session manager; its lock serializes concurrent
// status requests for that device so they share one session instead of racing
// to log in.
type deviceManager struct {
	mu  sync.Mutex
	mgr device.Driver
}

// New builds the HTTP handler tree. ui may be nil (no dashboard embedded);
// dataDir is where config backups are written.
func New(cfg *core.Config, ui fs.FS, dataDir string) *Server {
	s := &Server{cfg: cfg, ui: ui, dataDir: dataDir, managers: map[string]*deviceManager{}, reach: map[string]bool{}, codec: wax.Codec{}}
	warnIfAuthOff(cfg)

	// Config change-history store (full snapshots, local git). Best-effort:
	// a failure here disables history but never stops the server or a backup.
	base := dataDir
	if base == "" {
		base = "data"
	}
	if hs, err := backup.OpenHistory(filepath.Join(base, "history")); err != nil {
		log.Printf("config history disabled: %v", err)
	} else {
		s.history = hs
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("POST /api/devices", s.handleAddDevice)
	mux.HandleFunc("POST /api/devices/test", s.handleTestConnection)
	mux.HandleFunc("GET /api/devices/{name}/config", s.handleDeviceConfig)
	mux.HandleFunc("PUT /api/devices/{name}", s.handleUpdateDevice)
	mux.HandleFunc("DELETE /api/devices/{name}", s.handleRemoveDevice)
	mux.HandleFunc("GET /api/devices/{name}/status", s.handleDeviceStatus)
	mux.HandleFunc("GET /api/devices/{name}/status/cached", s.handleDeviceStatusCached)
	mux.HandleFunc("GET /api/devices/{name}/events", s.handleDeviceEvents)
	mux.HandleFunc("GET /api/devices/{name}/drift", s.handleDeviceDrift)
	mux.HandleFunc("POST /api/devices/{name}/backup", s.handleDeviceBackup)
	mux.HandleFunc("GET /api/devices/{name}/backups", s.handleListBackups)
	mux.HandleFunc("GET /api/devices/{name}/history", s.handleConfigHistory)
	mux.HandleFunc("GET /api/devices/{name}/history/diff", s.handleConfigHistoryDiff)
	mux.HandleFunc("POST /api/devices/{name}/restore", s.handleDeviceRestore)
	mux.HandleFunc("POST /api/devices/{name}/config/name", s.handleSetName)
	mux.HandleFunc("POST /api/devices/{name}/apply", s.handleDeviceApply)
	mux.HandleFunc("POST /api/devices/{name}/change", s.handleDeviceChange)
	mux.HandleFunc("DELETE /api/devices/{name}/ssids/{ssid}", s.handleDeleteSSID)
	mux.HandleFunc("POST /api/devices/{name}/firmware/check", s.handleFirmwareCheck)
	mux.HandleFunc("POST /api/devices/{name}/firmware/upgrade", s.handleFirmwareUpgrade)
	mux.HandleFunc("GET /api/devices/{name}/firmware/progress", s.handleFirmwareProgress)
	mux.HandleFunc("POST /api/config/reload", s.handleReload)
	mux.HandleFunc("GET /api/discover", s.handleDiscover)

	// Everything else is the SPA (or a placeholder if no UI was embedded).
	mux.Handle("/", s.staticHandler())
	s.mux = mux
	return s
}

// deviceView is the public shape of a device: inventory only, never credentials.
type deviceView struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Model string `json:"model"`
}

func (s *Server) handleDevices(w http.ResponseWriter, _ *http.Request) {
	cfg := s.config()
	views := make([]deviceView, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		views = append(views, deviceView{Name: d.Name, Host: d.Host, Model: d.Model})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": views})
}

// handleReload re-reads the config file and swaps it in, so a hand-edit to the
// YAML takes effect without a restart (the in-UI device edits swap the config
// in themselves). A config that fails to load is rejected wholesale — the
// server keeps running on the previous one.
func (s *Server) handleReload(w http.ResponseWriter, _ *http.Request) {
	if s.cfgPath == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "reload is not enabled (server was started without a config path)"})
		return
	}
	cfg, err := core.LoadConfig(s.cfgPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "note": "previous config still active"})
		return
	}
	s.swapConfig(cfg)
	writeJSON(w, http.StatusOK, map[string]any{"devices": len(cfg.Devices)})
}

// swapConfig installs a new config snapshot and discards session managers that
// no longer match, so the change takes effect without a restart. Shared by the
// reload endpoint and the config-write endpoints (which get the parsed config
// back from core after editing the file).
func (s *Server) swapConfig(cfg *core.Config) {
	s.cfgMu.Lock()
	old := s.cfg
	s.cfg = cfg
	s.cfgMu.Unlock()
	// Every deliberate load or edit lands here — re-baseline the file so the
	// out-of-band edit check only fires on changes made behind our back.
	s.rememberConfigFile()
	if old.Server.Auth != nil && cfg.Server.Auth == nil {
		warnIfAuthOff(cfg) // warn on the transition, not on every device edit
	}
	s.dropStaleManagers(old, cfg)
}

// warnIfAuthOff makes an unauthenticated deployment a deliberate choice: the
// server works fine without a login, but the operator should see what that
// means — this dashboard holds AP admin credentials and its backups contain
// WiFi passphrases.
func warnIfAuthOff(cfg *core.Config) {
	if cfg.Server.Auth == nil {
		log.Printf("WARNING: dashboard auth is OFF — anyone who can reach this server can read and control your access points; set server.auth.password in the config to require a login")
	}
}

// dropStaleManagers discards cached session managers whose device was removed
// or whose connection details changed, so the next request builds a fresh one.
// Unchanged devices keep their manager — and with it the AP's warm session
// (login slots are scarce; never burn one on a no-op reload).
func (s *Server) dropStaleManagers(old, cur *core.Config) {
	same := map[string]bool{}
	for _, d := range cur.Devices {
		for _, o := range old.Devices {
			if o.Name == d.Name && o.Host == d.Host && o.Username == d.Username && o.Password == d.Password {
				same[d.Name] = true
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.managers {
		if !same[name] {
			delete(s.managers, name)
		}
	}
}

func (s *Server) handleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	status, code, errBody := s.fetchStatus(r.Context(), dev)
	if errBody != nil {
		writeJSON(w, code, errBody)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleDeviceDrift(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	status, code, errBody := s.fetchStatus(r.Context(), dev)
	if errBody != nil {
		writeJSON(w, code, errBody)
		return
	}
	report := core.ComputeDrift(dev.Desired, observedSSIDs(status), observedRadios(status))
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleDeviceBackup(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if s.deviceBusy(w, dev.Name) {
		return
	}
	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	path, err := dm.mgr.Backup(r.Context(), s.deviceDataDir(dev.Name))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name})
		return
	}
	path, err = s.finishBackup(dev, path, time.Now())
	if err != nil {
		log.Printf("backup %s: %v", dev.Name, err) // best-effort
	}
	writeJSON(w, http.StatusOK, map[string]string{"device": dev.Name, "backup": path})
}

// handleSetName is the reference guarded write: it changes the AP name through
// the full backup → write → verify pipeline. It is the simplest safe write;
// richer writes (SSID/VLAN/radio) ride the same guarded pipeline.
func (s *Server) handleSetName(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if s.deviceBusy(w, dev.Name) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"name\": \"...\"}"})
		return
	}

	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !s.checkSerial(r.Context(), w, dev, dm.mgr) {
		return
	}
	res, err := dm.mgr.SetName(r.Context(), s.deviceDataDir(dev.Name), body.Name)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name})
		return
	}
	s.finishApplyBackup(dev, res)
	s.snapshotAfterApply(r.Context(), dev, dm, []*device.ApplyResult{res})
	code := http.StatusOK
	if !res.Applied {
		code = http.StatusConflict // wrote, but read-back did not confirm
	}
	writeJSON(w, code, res)
}

// handleDeviceRestore puts a stored backup back onto the device. THIS REBOOTS
// THE AP and drops every WiFi client on it — the most disruptive config
// operation there is. The stored (decrypted) archive is re-encrypted with the
// device's CURRENT admin password before upload, which is also the password
// the AP uses to decrypt it — so any snapshot is restorable no matter what the
// password was when it was taken.
//
// Guards, in order:
//   - the snapshot must exist in this device's backup directory and be (or
//     decrypt to) a complete AP archive — the AP itself rejects one without
//     tmp/decryptedKeys, so that's checked here first;
//   - a fresh backup is taken before the write (hard rule), and doubles as
//     the reference for the password check;
//   - the backup carries the AP's login-password file (sysconfig/shadow) and
//     a restore puts it back — so restoring a snapshot with a different one
//     ROLLS THE ADMIN PASSWORD BACK to that snapshot's day. That is refused
//     (409, passwordReverts=true) unless the request sets
//     acceptPasswordRevert.
//
// Success is judged solely by the session-reset check — a reboot kills the
// pre-restore session, so if that session still works, the restore did not
// take (409).
func (s *Server) handleDeviceRestore(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if s.deviceBusy(w, dev.Name) {
		return
	}
	var body struct {
		File                 string `json:"file"`
		AcceptPasswordRevert bool   `json:"acceptPasswordRevert"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil || body.File == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"file\": \"<archive from this device's backups>\"}"})
		return
	}
	name := filepath.Base(body.File)
	snap, err := os.ReadFile(filepath.Join(s.deviceDataDir(dev.Name), name))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such backup for " + dev.Name + ": " + name})
		return
	}
	// Snapshots are stored decrypted; one still encrypted (its password was
	// wrong at conversion time) is tried once more with today's password.
	if s.codec.IsEncrypted(snap) {
		if snap, err = s.codec.Decrypt(snap, dev.Password); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": name + " is still encrypted under a password that is not the current admin password — the AP would reject it. Restore is only possible for snapshots selfsight was able to decrypt.",
			})
			return
		}
	}
	if err := s.codec.ValidateArchive(snap); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": name + ": " + err.Error()})
		return
	}

	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !s.checkSerial(r.Context(), w, dev, dm.mgr) {
		return
	}

	// Hard rule: never write without a fresh backup taken immediately before.
	// It is also the reference for the password-revert check below.
	freshRaw, err := dm.mgr.Backup(r.Context(), s.deviceDataDir(dev.Name))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "restore aborted — pre-restore backup failed: " + err.Error(), "device": dev.Name})
		return
	}
	freshPath, err := s.finishBackup(dev, freshRaw, time.Now())
	if err != nil {
		log.Printf("pre-restore backup %s: %v", dev.Name, err)
	}
	reverts := s.passwordReverts(snap, freshPath)
	if reverts && !body.AcceptPasswordRevert {
		writeJSON(w, http.StatusConflict, map[string]any{
			"passwordReverts": true,
			"error": "this snapshot carries a DIFFERENT admin password than the device has now — restoring it rolls the login password back to that snapshot's day. Resend with acceptPasswordRevert=true to proceed; afterwards selfsight's configured password for " +
				dev.Name + " must be updated to the old one or the device becomes unreachable.",
		})
		return
	}

	enc, err := s.codec.Encrypt(snap, dev.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "re-encrypting snapshot: " + err.Error()})
		return
	}
	// A restore reboots the AP; the poll window must comfortably exceed how
	// long the device is unreachable. A live drill saw GarageAP take ~2 min to
	// reboot and answer again, tripping a 2-min window into a false "did not
	// answer" even though the restore took — so give it 5.
	res, err := dm.mgr.Restore(r.Context(), name, enc, 5*time.Minute)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name})
		return
	}
	code := http.StatusOK
	if !res.Rebooted {
		code = http.StatusConflict // uploaded, but no reboot: the restore did not take
	}
	writeJSON(w, code, map[string]any{
		"file": res.File, "rebooted": res.Rebooted, "passwordReverted": reverts && res.Rebooted,
	})
}

// passwordReverts reports whether restoring snapshot snap would change the
// device's web-admin login, by comparing the admin credential (name +
// password hash) it carries against the one in the fresh pre-restore backup
// at freshPath. That credential is stable across reboots — unlike
// sysconfig/shadow, which the device re-salts on every restart and so would
// falsely flag ordinary restores. Anything short of proof the two match
// counts as a revert; the caller then requires explicit consent, erring safe.
func (s *Server) passwordReverts(snap []byte, freshPath string) bool {
	fresh, err := os.ReadFile(freshPath)
	if err != nil || s.codec.IsEncrypted(fresh) {
		return true
	}
	snapCred, err1 := s.codec.AdminCredential(snap)
	freshCred, err2 := s.codec.AdminCredential(fresh)
	if err1 != nil || err2 != nil {
		return true
	}
	return snapCred != freshCred
}

// serialMatches enforces the device entry's recorded serial against the live
// one before a write-class operation. No serial recorded (or reported in st)
// means no check; a mismatch answers 409 and returns false — the host now
// points at different hardware and writing would push this entry's config onto
// the wrong unit.
func serialMatches(w http.ResponseWriter, dev *core.Device, st *device.Status) bool {
	if dev.Serial == "" || st == nil || st.System == nil {
		return true
	}
	live := st.System.Serial
	if live == "" || live == dev.Serial {
		return true
	}
	writeJSON(w, http.StatusConflict, map[string]string{
		"error": fmt.Sprintf("serial mismatch: %s is recorded as serial %s but the device at %s reports %s — refusing to write; if the hardware really changed, update the recorded serial (re-run the connection test in Edit, or fix config.yaml)",
			dev.Name, dev.Serial, dev.Host, live),
		"device": dev.Name,
	})
	return false
}

// checkSerial is serialMatches for handlers that don't otherwise read status:
// it fetches the live status (only when a serial is recorded, to avoid a
// gratuitous AP round-trip) and compares. Must be called with the device's
// manager lock held. Returns false when the request has been answered.
func (s *Server) checkSerial(ctx context.Context, w http.ResponseWriter, dev *core.Device, drv device.Driver) bool {
	if dev.Serial == "" {
		return true
	}
	st, err := drv.Status(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "serial check before write: " + err.Error(), "device": dev.Name,
		})
		return false
	}
	return serialMatches(w, dev, st)
}

// deviceDataDir is where a device's backups live: <dataDir>/backups/<device>.
func (s *Server) deviceDataDir(name string) string {
	base := s.dataDir
	if base == "" {
		base = "data"
	}
	return filepath.Join(base, "backups", name)
}

// fetchStatus reads a device's live status under its per-device lock, mapping a
// driver error to an HTTP status + JSON body (nil body on success).
func (s *Server) fetchStatus(ctx context.Context, dev *core.Device) (*device.Status, int, map[string]string) {
	if u := s.upgradeFor(dev.Name); u != nil {
		u.mu.Lock()
		running := u.Running
		u.mu.Unlock()
		if running {
			return nil, http.StatusServiceUnavailable, map[string]string{
				"error": "firmware upgrade in progress", "device": dev.Name,
			}
		}
	}
	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	status, err := dm.mgr.Status(ctx)
	// A canceled request (browser navigated away) says nothing about the AP —
	// only a completed attempt updates the reachability diary.
	if ctx.Err() == nil {
		s.noteReach(dev, err)
	}
	if err != nil {
		// A device still locked after a fresh login is genuinely Insight-managed
		// — a 409 (conflict with its current mode), not a 5xx.
		if errors.Is(err, device.ErrManaged) {
			return nil, http.StatusConflict, map[string]string{
				"error":  "device is Insight-managed; switch it to standalone to use the local API",
				"device": dev.Name,
			}
		}
		return nil, http.StatusBadGateway, map[string]string{"error": err.Error(), "device": dev.Name}
	}
	s.saveStatusCache(dev.Name, status)
	return status, http.StatusOK, nil
}

// bandToKey maps the driver's human band labels to the config's radio keys.
var bandToKey = map[string]string{"2.4 GHz": "2g", "5 GHz": "5g", "6 GHz": "6g"}

func observedSSIDs(st *device.Status) []core.ObservedSSID {
	out := make([]core.ObservedSSID, 0, len(st.SSIDs))
	for _, x := range st.SSIDs {
		out = append(out, core.ObservedSSID{
			Name: x.Name, VLAN: x.VLAN, Security: x.Security,
			Hidden: x.Hidden, Enabled: x.Enabled,
		})
	}
	return out
}

func observedRadios(st *device.Status) []core.ObservedRadio {
	if st.System == nil {
		return nil
	}
	// radioStatus comes from the radio-settings read, keyed by the same band
	// labels as the monitor read; nil (not observed) never drifts.
	on := map[string]*bool{}
	for i := range st.RadioSettings {
		on[st.RadioSettings[i].Band] = &st.RadioSettings[i].On
	}
	out := make([]core.ObservedRadio, 0, len(st.System.Radios))
	for _, r := range st.System.Radios {
		if key := bandToKey[r.Band]; key != "" {
			out = append(out, core.ObservedRadio{Band: key, Channel: r.Channel, Enabled: on[r.Band]})
		}
	}
	return out
}

// device returns the configured device by name, or nil.
func (s *Server) device(name string) *core.Device {
	cfg := s.config()
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// managerOpts lets tests shorten poll intervals; production uses the defaults.
var managerOpts []wax.Option

// managerFor returns the (lazily created, cached) session manager for a device.
func (s *Server) managerFor(dev *core.Device) *deviceManager {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dm := s.managers[dev.Name]; dm != nil {
		return dm
	}
	dm := &deviceManager{mgr: s.newManager(dev.Host, dev.Username, dev.Password)}
	s.managers[dev.Name] = dm
	return dm
}

// newManager builds a driver for a host, wiring up the persisted session
// path and (trust-on-first-use) certificate pin. This is the ONE place a
// vendor implementation is chosen; everything else speaks device.Driver.
// It does not require the host to be in the inventory — the add-device
// connection test uses it for a device that isn't configured yet, warming
// the very session the real driver will reuse once the device is added.
func (s *Server) newManager(host, user, pass string) device.Driver {
	sessPath, _ := wax.DefaultSessionPath(host)
	opts := managerOpts
	if pinPath, err := wax.DefaultPinPath(host); err == nil {
		opts = append(append([]wax.Option{}, opts...), wax.WithPinPath(pinPath))
	}
	return wax.NewManager(host, sessPath, user, pass, opts...)
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	cidr := r.URL.Query().Get("cidr")
	if cidr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ?cidr= (e.g. 192.168.1.0/24)"})
		return
	}
	found, err := discovery.Sweep(r.Context(), cidr, 64, 1500*time.Millisecond)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Mark which candidates are already in the inventory (by host).
	known := map[string]bool{}
	for _, d := range s.config().Devices {
		known[d.Host] = true
	}
	type cand struct {
		IP    string `json:"ip"`
		Model string `json:"model"`
		Known bool   `json:"known"`
	}
	out := make([]cand, 0, len(found))
	for _, c := range found {
		out = append(out, cand{IP: c.IP, Model: c.Model, Known: known[c.IP]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"candidates": out})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// MaxRequestBody bounds every JSON request body selfsight accepts. Its request
// bodies are all small — a device entry, a filename, a password — so this is
// generous. Without a cap the decoder buffers whatever it is sent, which turns
// any endpoint into a memory-exhaustion lever for anyone who can reach it.
const MaxRequestBody = 1 << 20 // 1 MiB

// decodeJSONBody reads a size-limited JSON body into v. Every handler decodes
// through this rather than json.NewDecoder(r.Body) directly, so the limit
// cannot be forgotten on a route added later.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBody)).Decode(v)
}
