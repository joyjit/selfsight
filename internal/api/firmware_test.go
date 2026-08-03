package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"selfsight/internal/core"
	"selfsight/internal/driver/wax"
)

// fwFake simulates the /LogFile firmware machinery: method 5 marks an update
// available, method 7 starts an upgrade, method 6 reports one download poll at
// 100% then one flash poll done, after which the "new" firmware version shows.
type fwFake struct {
	mu       sync.Mutex
	started  bool
	flashed  bool
	version  string
	newImage string
}

func (ap *fwFake) handle(w http.ResponseWriter, r *http.Request) {
	ap.mu.Lock()
	defer ap.mu.Unlock()
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
	if r.URL.Path == "/LogFile" {
		switch {
		case strings.Contains(s, `"method":3`), strings.Contains(s, `"method": 3`):
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(s, `"method":5`):
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(s, `"method":7`):
			ap.started = true
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(s, `"fwPercent":0`):
			_, _ = io.WriteString(w, `{"status":0,"percent":100}`)
		case strings.Contains(s, `"fwPercent":1`):
			ap.flashed = true
			ap.version = ap.newImage // "reboot" onto the new image
			_, _ = io.WriteString(w, `{"status":100,"percent":100}`)
		default:
			_, _ = io.WriteString(w, `{"status":0}`)
		}
		return
	}
	switch {
	case strings.Contains(s, "adminPasswd"):
		_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
	case strings.Contains(s, "sysSerialNumber"):
		fmt.Fprintf(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":%q},"basicSettings":{"apName":"AP","cloudStatus":"0"}}}`, ap.version)
	case strings.Contains(s, "ImageAvailable"):
		avail := "0"
		if !ap.flashed {
			avail = "1"
		}
		fmt.Fprintf(w, `{"status":0,"system":{"FwUpdate":{"ImageAvailable":%q,"ImageVersion":%q,"LastcheckedDate":"today","releasenotesurl":""}}}`, avail, ap.newImage)
	default:
		_, _ = io.WriteString(w, `{"status":1}`)
	}
}

func fwServer(t *testing.T, ap *fwFake) *Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(ap.handle))
	t.Cleanup(ts.Close)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	// Fast polls so the upgrade loop finishes in test time.
	old := managerOpts
	managerOpts = []wax.Option{wax.WithPollInterval(time.Millisecond)}
	t.Cleanup(func() { managerOpts = old })

	host := strings.TrimPrefix(ts.URL, "https://")
	cfg := &core.Config{
		Server:  core.Server{Listen: ":0"},
		Devices: []core.Device{{Name: "ap1", Host: host, Username: "admin", Password: "pw"}},
	}
	return New(cfg, nil, t.TempDir())
}

func TestFirmwareCheckEndpoint(t *testing.T) {
	ap := &fwFake{version: "V1", newImage: "V2"}
	s := fwServer(t, ap)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, apiRequest(http.MethodPost, "/api/devices/ap1/firmware/check", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("check: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var fw struct {
		UpdateAvailable bool
		AvailableImage  string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &fw); err != nil {
		t.Fatal(err)
	}
	if !fw.UpdateAvailable || fw.AvailableImage != "V2" {
		t.Errorf("check result wrong: %+v", fw)
	}
}

func TestFirmwareUpgradeLifecycle(t *testing.T) {
	ap := &fwFake{version: "V1", newImage: "V2"}
	s := fwServer(t, ap)

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, apiRequest(http.MethodPost, "/api/devices/ap1/firmware/upgrade", nil))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("upgrade start: want 202, got %d: %s", rr.Code, rr.Body.String())
	}

	// Poll progress until the background upgrade finishes.
	deadline := time.Now().Add(10 * time.Second)
	var final map[string]any
	for {
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/firmware/progress", nil))
		_ = json.Unmarshal(rr.Body.Bytes(), &final)
		if final["running"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upgrade never finished: %v", final)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if final["error"] != nil {
		t.Fatalf("upgrade error: %v", final["error"])
	}
	outcome, _ := final["outcome"].(map[string]any)
	if outcome == nil || outcome["confirmed"] != true || outcome["newVersion"] != "V2" {
		t.Fatalf("upgrade must be confirmed by a fresh version read-back: %v", final)
	}
	if outcome["backup"] == "" {
		t.Error("upgrade must take a pre-flash backup")
	}
	if !ap.started || !ap.flashed {
		t.Error("fake AP never saw the upgrade sequence")
	}
}

func TestSecondUpgradeRefusedWhileRunning(t *testing.T) {
	ap := &fwFake{version: "V1", newImage: "V2"}
	s := fwServer(t, ap)

	// Mark another device's upgrade as running (fleet-wide gate).
	u := s.upgradeFor("other")
	u.mu.Lock()
	u.Running = true
	u.mu.Unlock()

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, apiRequest(http.MethodPost, "/api/devices/ap1/firmware/upgrade", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("fleet-parallel upgrades must be refused: want 409, got %d", rr.Code)
	}

	// And the busy device itself answers 503 on status instead of hanging.
	u2 := s.upgradeFor("ap1")
	u2.mu.Lock()
	u2.Running = true
	u2.mu.Unlock()
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/status", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status during upgrade: want 503, got %d", rr.Code)
	}
}

// TestConcurrentUpgradesClaimOneSlot drives the actual race the fleet-wide
// "one AP at a time" rule exists to prevent: two upgrade requests for two
// different devices, in flight at the same time. The earlier refusal test
// pre-sets Running by hand, so it exercises the check but never the window
// between checking and claiming — which is where a serial round-trip to the AP
// used to sit. Exactly one request may be accepted.
func TestConcurrentUpgradesClaimOneSlot(t *testing.T) {
	ap := &fwFake{version: "V1", newImage: "V2"}
	s := fwServer(t, ap)

	// A second device on the same fake AP: the fleet gate is about the fleet,
	// not about one device's lock.
	cfg := s.config()
	devs := append([]core.Device{}, cfg.Devices...)
	devs = append(devs, core.Device{Name: "ap2", Host: devs[0].Host, Username: "admin", Password: "pw"})
	s.swapConfig(&core.Config{Server: cfg.Server, Devices: devs})

	var (
		start           = make(chan struct{})
		wg              sync.WaitGroup
		mu              sync.Mutex
		accepted, other int
	)
	for _, name := range []string{"ap1", "ap2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release both at once to overlap the check/claim window
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, apiRequest(http.MethodPost, "/api/devices/"+name+"/firmware/upgrade", nil))
			mu.Lock()
			defer mu.Unlock()
			if rr.Code == http.StatusAccepted {
				accepted++
			} else {
				other++
			}
		}()
	}
	close(start)
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("exactly one concurrent upgrade may be accepted, got %d accepted and %d refused", accepted, other)
	}
}

// TestUpgradeSlotReleasedWhenNothingStarts checks the other half of the claim:
// a claim that never turns into an upgrade must hand the slot back, or the
// fleet is wedged until restart.
func TestUpgradeSlotReleasedWhenNothingStarts(t *testing.T) {
	s := fwServer(t, &fwFake{version: "V1", newImage: "V2"})

	u, _, ok := s.claimUpgrade("ap1")
	if !ok {
		t.Fatal("first claim should succeed on an idle fleet")
	}
	if _, busy, ok := s.claimUpgrade("ap2"); ok {
		t.Fatal("a second claim must be refused while the slot is held")
	} else if busy != "ap1" {
		t.Errorf("refusal should name the holder, got %q", busy)
	}
	releaseUpgrade(u)
	if _, _, ok := s.claimUpgrade("ap2"); !ok {
		t.Fatal("slot must be reusable once released")
	}
}
