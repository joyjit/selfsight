package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"selfsight/internal/backup"
	"selfsight/internal/core"
)

// schedulerServer builds a *Server against the fake AP.
func schedulerServer(t *testing.T, ts *httptest.Server) *Server {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	host := strings.TrimPrefix(ts.URL, "https://")
	cfg := &core.Config{
		Server:  core.Server{Listen: ":0"},
		Devices: []core.Device{{Name: "ap1", Host: host, Model: "WAX610", Username: "admin", Password: "pw"}},
	}
	return New(cfg, nil, t.TempDir())
}

func TestBackupRoundStampsArchives(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)

	s.backupRound(context.Background())

	entries, err := os.ReadDir(s.deviceDataDir("ap1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 archive, got %d", len(entries))
	}
	// Timestamp prefix keeps same-day rounds from overwriting each other.
	stamped := regexp.MustCompile(`^\d{8}T\d{6}Z-WAX610-AP-Test-config\.tar$`)
	if !stamped.MatchString(entries[0].Name()) {
		t.Errorf("archive not timestamp-prefixed: %q", entries[0].Name())
	}
}

func TestPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	base := time.Now()
	for i, name := range []string{"old.tar", "mid.tar", "new.tar"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		ts := base.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, ts, ts); err != nil {
			t.Fatal(err)
		}
	}

	if err := pruneBackups(dir, 2); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 2 || left[0] != "mid.tar" || left[1] != "new.tar" {
		t.Errorf("prune must keep the 2 newest, left: %v", left)
	}

	// keep=0 means keep everything.
	if err := pruneBackups(dir, 0); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Error("keep=0 must not delete anything")
	}
}

func TestListBackupsEndpoint(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)

	dir := s.deviceDataDir("ap1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(dir, "a.tar")
	newer := filepath.Join(dir, "b.tar")
	for _, p := range []string{older, newer} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/backups", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Backups []struct {
			File string `json:"file"`
			Size int64  `json:"size"`
		} `json:"backups"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Backups) != 2 || got.Backups[0].File != "b.tar" || got.Backups[1].File != "a.tar" {
		t.Errorf("want newest-first [b.tar a.tar], got %+v", got.Backups)
	}

	// No backups yet (fresh device dir) must be an empty list, not an error.
	ts2 := fakeAP(false)
	t.Cleanup(ts2.Close)
	rr = httptest.NewRecorder()
	s2 := schedulerServer(t, ts2)
	s2.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/backups", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"backups":[]`) {
		t.Errorf("empty dir: want 200 with [], got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRestoreEndpointRequiresExistingArchive(t *testing.T) {
	ts := fakeAP(false)
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/devices/ap1/restore", strings.NewReader(`{"file":"nope.tar"}`))
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("restore of a nonexistent archive must 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// configFake is a fake AP whose backup download is settable, so a test can
// simulate the config staying the same or changing between watcher rounds.
type configFake struct {
	mu  sync.Mutex
	enc []byte
}

func (f *configFake) set(b []byte) {
	f.mu.Lock()
	f.enc = b
	f.mu.Unlock()
}

func (f *configFake) server() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/AP_login":
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed", HttpOnly: true})
		case r.URL.Path == "/wac510-backup":
			f.mu.Lock()
			b := f.enc
			f.mu.Unlock()
			w.Header().Set("Content-Disposition", `attachment; filename="WAX610-AP-Test-config.tar"`)
			_, _ = w.Write(b)
		case r.URL.Path == "/LogFile":
			_, _ = io.WriteString(w, `{"status":0}`)
		default:
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), "adminPasswd"):
				_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
			case r.Header.Get("security") == "":
				_, _ = io.WriteString(w, `{"status":401}`)
			default:
				_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9"}}}`)
			}
		}
	}))
}

// The watcher stores a backup only when the config changed since the last one:
// a first pull is kept, an identical second pull is discarded (no redundant
// archive or history commit), and a changed pull is kept — so history records
// exactly the distinct configs, never a clock-driven duplicate.
func TestBackupWatcherStoresOnlyOnChange(t *testing.T) {
	cfgA := "system:basicSettings:apName Home\nsystem:vap:ssid Guest\n"
	cfgB := "system:basicSettings:apName Home\nsystem:vap:ssid Lounge\n"
	encA, err := backup.Encrypt(mkBackupTar(t, cfgA, "shadow\n", true), "pw")
	if err != nil {
		t.Fatal(err)
	}
	encB, err := backup.Encrypt(mkBackupTar(t, cfgB, "shadow\n", true), "pw")
	if err != nil {
		t.Fatal(err)
	}

	fake := &configFake{}
	fake.set(encA)
	ts := fake.server()
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)

	countStored := func() int {
		t.Helper()
		entries, err := os.ReadDir(s.deviceDataDir("ap1"))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if !e.IsDir() {
				n++
			}
		}
		return n
	}
	historyLen := func() int {
		t.Helper()
		snaps, err := s.history.History("ap1")
		if err != nil {
			t.Fatal(err)
		}
		return len(snaps)
	}

	// First check: nothing stored yet, so the pull is kept and recorded.
	s.backupRound(context.Background())
	if got := countStored(); got != 1 {
		t.Fatalf("first check: want 1 stored backup, got %d", got)
	}
	if got := historyLen(); got != 1 {
		t.Fatalf("first check: want 1 history snapshot, got %d", got)
	}

	// Second check, identical config: the pull must be discarded — no new
	// archive on disk, no new history commit.
	s.backupRound(context.Background())
	if got := countStored(); got != 1 {
		t.Fatalf("unchanged config must not add a backup, got %d stored", got)
	}
	if got := historyLen(); got != 1 {
		t.Fatalf("unchanged config must not add history, got %d", got)
	}

	// Config changes out-of-band: the next check keeps it. (Assert on history,
	// which dedups by content, so a same-second timestamp collision on the
	// archive filename can't make this flaky.)
	fake.set(encB)
	s.backupRound(context.Background())
	if got := historyLen(); got != 2 {
		t.Fatalf("changed config must be recorded, got %d history snapshots", got)
	}
}

// The watcher runs an initial check shortly after startup (not a whole interval
// later), so a change made while selfsight was down is caught promptly.
func TestBackupWatcherInitialCheck(t *testing.T) {
	enc, err := backup.Encrypt(mkBackupTar(t, "system:x 1\n", "shadow\n", true), "pw")
	if err != nil {
		t.Fatal(err)
	}
	fake := &configFake{}
	fake.set(enc)
	ts := fake.server()
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)
	// Tiny startup delay, long routine interval: the first check must fire
	// almost immediately, then the loop parks on the interval.
	s.cfg.Server.BackupCheck = &core.BackupCheck{StartupDelay: "1ms", Interval: "1h"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunBackupWatcher(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(s.deviceDataDir("ap1"))
		n := 0
		for _, e := range entries {
			if !e.IsDir() {
				n++
			}
		}
		if n >= 1 {
			return // initial check stored the backup — success
		}
		if time.Now().After(deadline) {
			t.Fatal("initial check did not store a backup within the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
