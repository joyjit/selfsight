package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"selfsight/internal/core"
)

func testConfig() *core.Config {
	return &core.Config{
		Server: core.Server{Listen: ":8080"},
		Devices: []core.Device{
			{Name: "living-room", Host: "192.0.2.20", Model: "WAX610", Username: "admin", Password: "s3cret"},
		},
	}
}

func TestDevicesNeverLeakCredentials(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "s3cret") || strings.Contains(strings.ToLower(body), "password") {
		t.Fatalf("device listing leaked credentials: %s", body)
	}
	var got struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || got.Devices[0]["name"] != "living-room" {
		t.Fatalf("devices = %v", got.Devices)
	}
	if _, ok := got.Devices[0]["password"]; ok {
		t.Error("password field present in device view")
	}
}

func TestDeviceStatusUnknownDevice(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/nope/status", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr.Code)
	}
}

func TestNoUIServesPlaceholder(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	b, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(b), "no dashboard embedded") {
		t.Errorf("expected placeholder, got %q", string(b))
	}
}

// fakeAP simulates a WAX AP for the live-status endpoint: it seeds the login
// cookie on GET /AP_login, hands out a token on the credential POST (only if the
// seed cookie is present), and returns a minimal system-info read for a signed
// request. managed=true makes it stay locked (status 100) even after login.
func fakeAP(managed bool) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/AP_login" {
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed", HttpOnly: true})
			return
		}
		if r.URL.Path == "/wac510-backup" {
			w.Header().Set("Content-Disposition", `attachment; filename="WAX610-AP-Test-config.tar"`)
			_, _ = w.Write([]byte("PK-fake-encrypted-archive"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/LogFile" {
			_, _ = io.WriteString(w, `{"status":0}`) // backup authorized
			return
		}
		switch {
		case strings.Contains(string(body), "adminPasswd"):
			if !strings.Contains(r.Header.Get("Cookie"), "lhttpdsid=seed") {
				_, _ = io.WriteString(w, `{"status":100}`)
				return
			}
			_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
		case r.Header.Get("security") == "":
			_, _ = io.WriteString(w, `{"status":401}`)
		case managed:
			_, _ = io.WriteString(w, `{"status":100}`)
		case strings.Contains(string(body), "sysSerialNumber"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9","ipAddress":"192.0.2.7"},"basicSettings":{"apName":"AP-Test","cloudStatus":"0"}}}`)
		default:
			_, _ = io.WriteString(w, `{"status":1}`) // other best-effort reads: omitted
		}
	}))
}

func serverForAP(t *testing.T, ts *httptest.Server) http.Handler {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir()) // keep session files out of the real cache
	host := strings.TrimPrefix(ts.URL, "https://")
	cfg := &core.Config{
		Server:  core.Server{Listen: ":0"},
		Devices: []core.Device{{Name: "ap1", Host: host, Model: "WAX610", Username: "admin", Password: "pw"}},
	}
	return New(cfg, nil, t.TempDir())
}

func TestDeviceStatusLive(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	srv := serverForAP(t, ts)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		System struct {
			Name, Serial, Firmware string
			Standalone             bool
		} `json:"system"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.System.Name != "AP-Test" || got.System.Serial != "S1" || got.System.Firmware != "V9" {
		t.Errorf("wrong system info: %+v", got.System)
	}
	if !got.System.Standalone {
		t.Errorf("expected standalone")
	}
}

func TestDeviceDrift(t *testing.T) {
	ts := fakeAP(false) // returns system-info but no SSIDs
	t.Cleanup(ts.Close)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	host := strings.TrimPrefix(ts.URL, "https://")
	cfg := &core.Config{
		Server: core.Server{Listen: ":0"},
		Devices: []core.Device{{
			Name: "ap1", Host: host, Username: "admin", Password: "pw",
			Desired: core.Desired{SSIDs: []core.SSID{{Name: "HomeNet", VLAN: 1, Security: "wpa2-psk"}}},
		}},
	}
	srv := New(cfg, nil, t.TempDir())

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/drift", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var rep struct {
		InSync bool `json:"inSync"`
		Items  []struct {
			Scope, Field, Observed string
			InSync                 bool
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.InSync {
		t.Fatal("declared SSID absent on device should drift")
	}
	if len(rep.Items) != 1 || rep.Items[0].Scope != "ssid:HomeNet" || rep.Items[0].Observed != "missing" {
		t.Errorf("unexpected drift items: %+v", rep.Items)
	}
}

func TestDeviceBackup(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	srv := serverForAP(t, ts)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/backup", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got struct{ Backup string }
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got.Backup, "WAX610-AP-Test-config.tar") {
		t.Fatalf("unexpected backup path: %q", got.Backup)
	}
	data, err := os.ReadFile(got.Backup)
	if err != nil {
		t.Fatalf("backup file not written: %v", err)
	}
	if string(data) != "PK-fake-encrypted-archive" {
		t.Errorf("backup content wrong: %q", data)
	}
}

func TestSetNameGuardedWrite(t *testing.T) {
	// The status fake AP is stateless on writes, so drive a tiny stateful one:
	// login, backup, store apName on write, echo it on read-back.
	var stored string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/AP_login" {
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed"})
			return
		}
		if r.URL.Path == "/wac510-backup" {
			w.Header().Set("Content-Disposition", `attachment; filename="b.tar"`)
			_, _ = w.Write([]byte("archive"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		switch {
		case r.URL.Path == "/LogFile":
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(s, "adminPasswd"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
		case strings.Contains(s, "sysSerialNumber"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9"},"basicSettings":{"apName":`+mustJSON(stored)+`,"cloudStatus":"0"}}}`)
		case strings.Contains(s, "apName"):
			var p struct {
				System struct {
					Basic struct {
						APName string `json:"apName"`
					} `json:"basicSettings"`
				} `json:"system"`
			}
			_ = json.Unmarshal(body, &p)
			stored = p.System.Basic.APName
			_, _ = io.WriteString(w, `{"status":0}`)
		default:
			_, _ = io.WriteString(w, `{"status":1}`)
		}
	}))
	t.Cleanup(ts.Close)
	srv := serverForAP(t, ts)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/devices/ap1/config/name", strings.NewReader(`{"name":"Kitchen"}`))
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var res struct {
		Applied  bool
		Backup   string
		Observed string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Backup == "" || !strings.Contains(res.Observed, "Kitchen") {
		t.Errorf("guarded write result wrong: %+v", res)
	}
}

func mustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestDeviceStatusManagedIs409(t *testing.T) {
	ts := fakeAP(true) // stays locked even after a fresh login
	t.Cleanup(ts.Close)
	srv := serverForAP(t, ts)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/status", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409 for managed device, got %d: %s", rr.Code, rr.Body.String())
	}
}
