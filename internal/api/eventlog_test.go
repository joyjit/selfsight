package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"selfsight/internal/device"
)

func readEvents(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// One line per reachability flip — a flapping check must not fill the diary
// with one line per poll, and the first successful contact is not news.
func TestReachLogsOnlyTransitions(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	dev := &srv.config().Devices[0]
	down := errors.New("dial tcp: connection refused")

	srv.noteReach(dev, nil)  // first contact, fine: silent
	srv.noteReach(dev, nil)  // still fine: silent
	srv.noteReach(dev, down) // flip: logged
	srv.noteReach(dev, down) // still down: silent
	srv.noteReach(dev, nil)  // back: logged

	lines := readEvents(t, srv.deviceEventPath(dev.Name))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines (down, back), got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "no answer at 192.0.2.20") || !strings.Contains(lines[0], "connection refused") {
		t.Errorf("down line should carry the address and the error: %q", lines[0])
	}
	if !strings.Contains(lines[1], "answering again at 192.0.2.20") {
		t.Errorf("recovery line wrong: %q", lines[1])
	}
}

// A device that answers "Insight-managed" answered — that is not unreachable.
func TestReachManagedCountsAsAnswering(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	dev := &srv.config().Devices[0]
	srv.noteReach(dev, device.ErrManaged)
	if lines := readEvents(t, srv.deviceEventPath(dev.Name)); lines != nil {
		t.Fatalf("managed answer must not read as unreachable: %v", lines)
	}
}

// Overwriting the cached reading is the one moment an identity change is
// visible; every differing identity field gets a line, live counters none.
func TestIdentityChangesAreLoggedOnCacheOverwrite(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	first := &device.Status{System: &device.SystemInfo{
		Name: "GarageAP", Serial: "S1", MAC: "aa:bb", Firmware: "V1", IP: "192.0.2.183", Gateway: "192.0.2.1", Uptime: "1 day",
	}}
	second := &device.Status{System: &device.SystemInfo{
		Name: "GarageAP", Serial: "S1", MAC: "aa:bb", Firmware: "V1", IP: "192.0.2.90", Gateway: "192.0.2.1", Uptime: "2 days",
	}}
	srv.saveStatusCache("living-room", first)
	srv.saveStatusCache("living-room", second)

	lines := readEvents(t, srv.deviceEventPath("living-room"))
	if len(lines) != 1 {
		t.Fatalf("exactly the changed ip should be logged, got: %v", lines)
	}
	if !strings.Contains(lines[0], "it now reports ip 192.0.2.90 (was 192.0.2.183)") {
		t.Errorf("ip change line wrong: %q", lines[0])
	}

	// Same reading again: uptime moved, identity didn't — no new line.
	srv.saveStatusCache("living-room", second)
	if lines := readEvents(t, srv.deviceEventPath("living-room")); len(lines) != 1 {
		t.Fatalf("unchanged identity must not log: %v", lines)
	}
}

// An edit to the config file the server didn't make itself is logged (once) by
// the watcher's check; the server's own writes re-baseline silently.
func TestOutOfBandConfigEditIsLogged(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(testConfig(), nil, dir)
	srv.EnableReload(cfgPath)

	srv.checkConfigFile() // nothing changed: silent
	if lines := readEvents(t, srv.fleetEventPath()); lines != nil {
		t.Fatalf("unchanged file must not log: %v", lines)
	}

	if err := os.WriteFile(cfgPath, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.checkConfigFile()
	srv.checkConfigFile() // the same edit is reported once, not every round
	lines := readEvents(t, srv.fleetEventPath())
	if len(lines) != 1 || !strings.Contains(lines[0], "changed on disk, not via the dashboard") {
		t.Fatalf("want one out-of-band line, got: %v", lines)
	}
}

// The events endpoint serves the tail of the log as JSON.
func TestDeviceEventsEndpoint(t *testing.T) {
	srv := New(testConfig(), nil, t.TempDir())
	srv.logDeviceEvent("living-room", "no answer at 192.0.2.20: boom")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/living-room/events", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Events []eventView `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Events) != 1 || !strings.Contains(got.Events[0].Message, "no answer") || got.Events[0].Time == "" {
		t.Fatalf("events = %+v", got.Events)
	}

	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/nope/events", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown device: want 404, got %d", rr.Code)
	}
}
