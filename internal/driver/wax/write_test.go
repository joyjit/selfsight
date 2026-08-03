package wax

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// applyAP is a small stateful fake AP for apply tests: it logs in, stores an
// apName write, and echoes the stored name on a system-info read. lie=true makes
// the read-back report a different name than was written (a write that "lied").
type applyAP struct {
	name        string
	lie         bool
	backupFails bool
	wrote       bool
}

func (ap *applyAP) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/AP_login":
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed"})
			return
		case r.URL.Path == "/wac510-backup":
			w.Header().Set("Content-Disposition", `attachment; filename="b.tar"`)
			_, _ = w.Write([]byte("archive"))
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/LogFile" {
			if ap.backupFails {
				_, _ = io.WriteString(w, `{"status":1}`) // backup authorize refused
			} else {
				_, _ = io.WriteString(w, `{"status":0}`)
			}
			return
		}
		s := string(body)
		switch {
		case strings.Contains(s, "adminPasswd"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
		case strings.Contains(s, "sysSerialNumber"): // read-back
			shown := ap.name
			if ap.lie {
				shown = "WRONG"
			}
			_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9"},"basicSettings":{"apName":`+jsonStr(shown)+`,"cloudStatus":"0"}}}`)
		case strings.Contains(s, "apName"): // write
			var p struct {
				System struct {
					Basic struct {
						APName string `json:"apName"`
					} `json:"basicSettings"`
				} `json:"system"`
			}
			_ = json.Unmarshal(body, &p)
			ap.name = p.System.Basic.APName
			ap.wrote = true
			_, _ = io.WriteString(w, `{"status":0}`)
		default:
			_, _ = io.WriteString(w, `{"status":1}`)
		}
	}))
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

func applyManager(t *testing.T, ap *applyAP) (*Manager, *httptest.Server) {
	t.Helper()
	ts := ap.server(t)
	host := strings.TrimPrefix(ts.URL, "https://")
	sess := t.TempDir() + "/sess.json"
	return NewManager(host, sess, "admin", "pw", WithHTTPClient(ts.Client())), ts
}

func TestApplySucceedsWhenReadBackConfirms(t *testing.T) {
	ap := &applyAP{name: "Old"}
	mgr, ts := applyManager(t, ap)
	defer ts.Close()

	res, err := mgr.Apply(context.Background(), t.TempDir(), APNameChange("NewName"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Errorf("expected applied, got %+v", res)
	}
	if res.Backup == "" {
		t.Error("apply must take a backup before writing")
	}
	if !strings.Contains(res.Observed, "NewName") {
		t.Errorf("observed = %q", res.Observed)
	}
}

func TestApplyRejectsLyingWrite(t *testing.T) {
	ap := &applyAP{name: "Old", lie: true} // write "succeeds" but read-back differs
	mgr, ts := applyManager(t, ap)
	defer ts.Close()

	res, err := mgr.Apply(context.Background(), t.TempDir(), APNameChange("NewName"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied {
		t.Error("a write must not be reported applied when read-back disagrees")
	}
}

func TestApplyAbortsWhenBackupFails(t *testing.T) {
	ap := &applyAP{name: "Old", backupFails: true}
	mgr, ts := applyManager(t, ap)
	defer ts.Close()

	_, err := mgr.Apply(context.Background(), t.TempDir(), APNameChange("NewName"))
	if err == nil {
		t.Fatal("apply must abort when the pre-write backup fails")
	}
	if ap.wrote {
		t.Error("no write may happen if the backup failed")
	}
}

func TestDeleteSSIDSlot(t *testing.T) {
	// The ssid-delete fixture proves the wire shape; the fake AP only answers
	// requests that match a fixture byte-for-byte (canonically), so a drifted
	// payload fails loudly.
	c := newTestClient(t, newFakeAP(t))
	if err := c.DeleteSSIDSlot(context.Background(), "SSID2"); err != nil {
		t.Fatalf("delete SSID2: %v", err)
	}
}

func TestDeleteSSIDSlotRefusesPrimary(t *testing.T) {
	// SSID1 is the device's primary network — refused at the driver level,
	// before any HTTP happens (the client has no live server here).
	c := New("192.0.2.1")
	c.SetSession("tok", "sid")
	if err := c.DeleteSSIDSlot(context.Background(), "SSID1"); err == nil ||
		!strings.Contains(err.Error(), "SSID1") {
		t.Fatalf("deleting SSID1 must be refused, got %v", err)
	}
}

func TestWriteSocketToleratesRadioBounce(t *testing.T) {
	// A write whose response never arrives (radio bounce) must not be treated as
	// a failure — the caller verifies by read-back. Simulate with a server that
	// hangs up: build a client pointed at a closed server.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	host := strings.TrimPrefix(ts.URL, "https://")
	c := New(host, WithHTTPClient(ts.Client()))
	c.SetSession("tok", "sid")
	ts.Close() // now connections fail -> transport error

	if err := c.SetAPName(context.Background(), "X"); err != nil {
		t.Errorf("transport failure on a write must be tolerated (verify decides), got %v", err)
	}
}
