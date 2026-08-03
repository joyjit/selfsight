package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"selfsight/internal/core"
)

// serverWithConfig writes body to a temp config file, loads it, and returns a
// server with config-write/reload enabled against that file.
func serverWithConfig(t *testing.T, body string) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, body)
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil, t.TempDir())
	s.EnableReload(path)
	return s, path
}

func doReq(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	s.ServeHTTP(rr, r)
	return rr
}

func TestAddDeviceEndpoint(t *testing.T) {
	s, path := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")

	rr := doReq(t, s, http.MethodPost, "/api/devices",
		`{"name":"beta","host":"192.0.2.9","username":"admin","password":"pw"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	// Live inventory now shows both, and the file on disk has beta.
	if n := deviceNames(t, s); len(n) != 2 || n[1] != "beta" {
		t.Fatalf("inventory not updated: %v", n)
	}
	if cfg, err := core.LoadConfig(path); err != nil || len(cfg.Devices) != 2 {
		t.Fatalf("file not written: %v %v", cfg, err)
	}
}

func TestAddDuplicateEndpoint(t *testing.T) {
	s, _ := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	rr := doReq(t, s, http.MethodPost, "/api/devices",
		`{"name":"alpha","host":"h2","username":"u"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate must 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAddInvalidDeviceRejected(t *testing.T) {
	s, _ := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	// Missing host — core validation must refuse it, inventory unchanged.
	rr := doReq(t, s, http.MethodPost, "/api/devices", `{"name":"beta","username":"u"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid device must 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if n := deviceNames(t, s); len(n) != 1 {
		t.Fatalf("inventory changed on a rejected add: %v", n)
	}
}

func TestUpdateDeviceEndpoint(t *testing.T) {
	s, path := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	rr := doReq(t, s, http.MethodPut, "/api/devices/alpha",
		`{"name":"alpha","host":"h9","username":"u","desired":{"ssids":[{"name":"Net","security":"wpa2-psk","passphrase":"secret"}]}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Devices[0]
	if d.Host != "h9" || len(d.Desired.SSIDs) != 1 || d.Desired.SSIDs[0].Name != "Net" {
		t.Fatalf("update not applied: %+v", d)
	}
}

func TestUpdatePreservesPasswordWhenBlank(t *testing.T) {
	// The UI never receives the stored password; editing with a blank password
	// must keep the existing one, not clear it.
	s, path := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u, password: keepme}\n")
	rr := doReq(t, s, http.MethodPut, "/api/devices/alpha",
		`{"name":"alpha","host":"h2","username":"u"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devices[0].Password != "keepme" {
		t.Fatalf("password should be preserved, got %q", cfg.Devices[0].Password)
	}
}

func TestUpdateKeepsEnvRefPasswordUnexpanded(t *testing.T) {
	// The quick-action / edit flow updates a device with a blank password
	// ("keep"). A password stored as ${VAR} must survive VERBATIM in the file —
	// preserving the runtime (env-expanded) value would write the real secret
	// into a config that is deliberately secret-free. Regression: caught live
	// on the first dashboard write drill (2026-07-13).
	t.Setenv("WRITE_TEST_PW", "real-secret")
	s, path := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u, password: \"${WRITE_TEST_PW}\"}\n")

	rr := doReq(t, s, http.MethodPut, "/api/devices/alpha",
		`{"name":"alpha","host":"h1","username":"u","desired":{"ssids":[{"name":"Net","hidden":true}]}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "real-secret") {
		t.Fatalf("the expanded secret leaked into the config file:\n%s", raw)
	}
	if !strings.Contains(string(raw), "${WRITE_TEST_PW}") {
		t.Fatalf("the ${VAR} reference must survive the edit verbatim:\n%s", raw)
	}
	// And the runtime config still resolves the real password.
	if dev := s.device("alpha"); dev == nil || dev.Password != "real-secret" {
		t.Fatalf("runtime config must carry the expanded password, got %+v", s.device("alpha"))
	}
}

func TestUpdatePreservesSerialWhenBlank(t *testing.T) {
	// Serial pins the entry to a physical unit; an edit that doesn't send one
	// (older client, untouched field) must keep it. Sending one replaces it.
	s, path := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, serial: SER-1, username: u}\n")
	rr := doReq(t, s, http.MethodPut, "/api/devices/alpha",
		`{"name":"alpha","host":"h2","username":"u"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devices[0].Serial != "SER-1" {
		t.Fatalf("serial should be preserved, got %q", cfg.Devices[0].Serial)
	}

	rr = doReq(t, s, http.MethodPut, "/api/devices/alpha",
		`{"name":"alpha","host":"h2","serial":"SER-2","username":"u"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if cfg, _ = core.LoadConfig(path); cfg.Devices[0].Serial != "SER-2" {
		t.Fatalf("explicit serial should replace, got %q", cfg.Devices[0].Serial)
	}
}

func TestRenameMovesBackupsDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	s := New(cfg, nil, dataDir)
	s.EnableReload(path)

	oldDir := filepath.Join(dataDir, "backups", "alpha")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "b.tar"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	rr := doReq(t, s, http.MethodPut, "/api/devices/alpha",
		`{"name":"attic","host":"h1","username":"u"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "backups", "attic", "b.tar")); err != nil {
		t.Fatalf("backup history must move with the rename: %v", err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("old backups dir should be gone, stat: %v", err)
	}
}

func TestGetDeviceConfigOmitsPassword(t *testing.T) {
	s, _ := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u, password: s3cret, desired: {ssids: [{name: Net, security: wpa2-psk}]}}\n")
	rr := doReq(t, s, http.MethodGet, "/api/devices/alpha/config", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "s3cret") {
		t.Fatalf("config leaked the password: %s", body)
	}
	if !strings.Contains(body, `"hasPassword":true`) || !strings.Contains(body, "Net") {
		t.Errorf("config should report hasPassword and the desired ssid: %s", body)
	}
}

func TestUpdateUnknownDeviceEndpoint(t *testing.T) {
	s, _ := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	rr := doReq(t, s, http.MethodPut, "/api/devices/ghost",
		`{"name":"ghost","host":"h","username":"u"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown device must 404, got %d", rr.Code)
	}
}

func TestRemoveDeviceEndpoint(t *testing.T) {
	s, path := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n  - {name: beta, host: h2, username: u}\n")
	rr := doReq(t, s, http.MethodDelete, "/api/devices/beta", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if n := deviceNames(t, s); len(n) != 1 || n[0] != "alpha" {
		t.Fatalf("beta not removed: %v", n)
	}
	if cfg, _ := core.LoadConfig(path); len(cfg.Devices) != 1 {
		t.Fatalf("file still has beta")
	}
}

func TestRemoveUnknownDeviceEndpoint(t *testing.T) {
	s, _ := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	rr := doReq(t, s, http.MethodDelete, "/api/devices/ghost", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr.Code)
	}
}

func TestWriteEndpointsDisabledWithoutConfigPath(t *testing.T) {
	// A server built without EnableReload has no config path, so every write
	// endpoint must answer 501 rather than silently doing nothing.
	s := New(testConfig(), nil, t.TempDir())
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/devices", `{"name":"x","host":"h","username":"u"}`},
		{http.MethodPut, "/api/devices/living-room", `{"name":"living-room","host":"h","username":"u"}`},
		{http.MethodDelete, "/api/devices/living-room", ""},
	} {
		rr := doReq(t, s, c.method, c.path, c.body)
		if rr.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: want 501, got %d", c.method, c.path, rr.Code)
		}
	}
}

func TestTestConnectionEndpoint(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	host := strings.TrimPrefix(ts.URL, "https://")

	s := New(testConfig(), nil, t.TempDir())
	rr := doReq(t, s, http.MethodPost, "/api/devices/test",
		`{"host":"`+host+`","username":"admin","password":"pw"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) || !strings.Contains(rr.Body.String(), "AP-Test") {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

func TestTestConnectionManaged(t *testing.T) {
	ts := fakeAP(true) // stays locked even after login
	t.Cleanup(ts.Close)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	host := strings.TrimPrefix(ts.URL, "https://")

	s := New(testConfig(), nil, t.TempDir())
	rr := doReq(t, s, http.MethodPost, "/api/devices/test",
		`{"host":"`+host+`","username":"admin","password":"pw"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("Insight-managed AP must 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestOversizeBodyRejected checks the request-body ceiling. Without it the JSON
// decoder buffers whatever it is handed, so any endpoint becomes a memory lever
// for anyone who can reach the server — which, with auth off, is the whole LAN.
func TestOversizeBodyRejected(t *testing.T) {
	s, _ := serverWithConfig(t, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	huge := `{"name":"beta","host":"192.0.2.9","username":"admin","password":"` +
		strings.Repeat("x", MaxRequestBody+1) + `"}`
	rr := doReq(t, s, http.MethodPost, "/api/devices", huge)
	if rr.Code == http.StatusOK || rr.Code == http.StatusCreated {
		t.Fatalf("an oversized body must be refused, got %d", rr.Code)
	}
	if n := len(s.config().Devices); n != 1 {
		t.Errorf("no device should have been added, inventory has %d", n)
	}
}
