package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"selfsight/internal/core"
)

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func deviceNames(t *testing.T, s *Server) []string {
	t.Helper()
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	var got struct {
		Devices []struct{ Name string } `json:"devices"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got.Devices))
	for _, d := range got.Devices {
		names = append(names, d.Name)
	}
	return names
}

func TestReloadSwapsConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil, t.TempDir())
	s.EnableReload(path)

	if n := deviceNames(t, s); len(n) != 1 || n[0] != "alpha" {
		t.Fatalf("before reload: %v", n)
	}

	writeConfig(t, path, "devices:\n  - {name: alpha, host: h1, username: u}\n  - {name: beta, host: h2, username: u}\n")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/reload", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("reload: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if n := deviceNames(t, s); len(n) != 2 || n[1] != "beta" {
		t.Fatalf("after reload: %v", n)
	}
}

func TestReloadRejectsBadConfigAndKeepsOld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, "devices:\n  - {name: alpha, host: h1, username: u}\n")
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil, t.TempDir())
	s.EnableReload(path)

	writeConfig(t, path, "devices: [{name: broken}]\n") // host/username missing
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/reload", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad config must 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if n := deviceNames(t, s); len(n) != 1 || n[0] != "alpha" {
		t.Fatalf("old config must survive a failed reload: %v", n)
	}
}

func TestReloadDisabledWithoutPath(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/reload", nil))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("want 501 when reload is not enabled, got %d", rr.Code)
	}
}

func TestReloadDropsOnlyStaleManagers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, strings.Join([]string{
		"devices:",
		"  - {name: keep, host: h1, username: u, password: p}",
		"  - {name: rehost, host: h2, username: u, password: p}",
		"  - {name: gone, host: h3, username: u, password: p}",
	}, "\n")+"\n")
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	s := New(cfg, nil, t.TempDir())
	s.EnableReload(path)

	// Materialize a manager per device (as requests would).
	for i := range cfg.Devices {
		s.managerFor(&cfg.Devices[i])
	}

	writeConfig(t, path, strings.Join([]string{
		"devices:",
		"  - {name: keep, host: h1, username: u, password: p}",
		"  - {name: rehost, host: h9, username: u, password: p}", // host changed
	}, "\n")+"\n")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/config/reload", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("reload: %d: %s", rr.Code, rr.Body.String())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.managers["keep"]; !ok {
		t.Error("unchanged device must keep its warm-session manager")
	}
	if _, ok := s.managers["rehost"]; ok {
		t.Error("device with a changed host must get a fresh manager")
	}
	if _, ok := s.managers["gone"]; ok {
		t.Error("removed device must not keep a manager")
	}
}
