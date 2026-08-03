package wax

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// restoreAP fakes the restore flow: it accepts the multipart upload and then —
// if reboots=true — starts rejecting the old session (status 401), which is
// exactly how a real reboot manifests to the session-reset check.
type restoreAP struct {
	mu           sync.Mutex
	reboots      bool
	gotFile      string
	gotField     bool
	gotPassword  string
	uploaded     []byte
	rebootedView bool // after "reboot", reads with the old session fail
}

func (ap *restoreAP) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap.mu.Lock()
		defer ap.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/AP_login":
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed"})
			return
		case r.URL.Path == "/restoreSettings":
			ap.gotPassword = r.Header.Get("password")
			f, hdr, err := r.FormFile("file")
			if err == nil {
				ap.gotField = true
				ap.gotFile = hdr.Filename
				ap.uploaded, _ = io.ReadAll(f)
				_ = f.Close()
			}
			if ap.reboots {
				ap.rebootedView = true
			}
			// The real AP's status here is untrustworthy; return one anyway.
			_, _ = io.WriteString(w, `{"status":0}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		switch {
		case strings.Contains(s, "adminPasswd"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
		case strings.Contains(s, "sysSerialNumber"):
			if ap.rebootedView {
				_, _ = io.WriteString(w, `{"status":401}`) // old session died with the reboot
				return
			}
			_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9"},"basicSettings":{"apName":"AP","cloudStatus":"0"}}}`)
		default:
			_, _ = io.WriteString(w, `{"status":1}`)
		}
	}))
}

func restoreManager(t *testing.T, ap *restoreAP) (*Manager, *httptest.Server) {
	t.Helper()
	ts := ap.server(t)
	host := strings.TrimPrefix(ts.URL, "https://")
	m := NewManager(host, t.TempDir()+"/sess.json", "admin", "pw", WithHTTPClient(ts.Client()))
	m.client.pollInterval = time.Millisecond
	return m, ts
}

func TestRestoreConfirmedBySessionReset(t *testing.T) {
	ap := &restoreAP{reboots: true}
	mgr, ts := restoreManager(t, ap)
	defer ts.Close()

	res, err := mgr.Restore(context.Background(), "b.tar", []byte("archive"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rebooted {
		t.Error("old session was killed — the restore must report rebooted")
	}
	if !ap.gotField || ap.gotFile != "b.tar" {
		t.Errorf("upload must be multipart field 'file' with the archive name; got field=%v name=%q", ap.gotField, ap.gotFile)
	}
	if ap.gotPassword != "pw" {
		t.Errorf("admin password must travel as a header, got %q", ap.gotPassword)
	}
	if !bytes.Equal(ap.uploaded, []byte("archive")) {
		t.Error("uploaded bytes differ from the archive")
	}
}

func TestRestoreNotTakenWhenSessionSurvives(t *testing.T) {
	ap := &restoreAP{reboots: false} // upload "accepted" but no reboot follows
	mgr, ts := restoreManager(t, ap)
	defer ts.Close()

	res, err := mgr.Restore(context.Background(), "b.tar", []byte("archive"), 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rebooted {
		t.Error("the pre-restore session still authenticates — restore must NOT be reported as taken")
	}
}

func TestRestoreRejectsBadArchives(t *testing.T) {
	c := New("192.0.2.1")
	c.SetSession("tok", "sid")
	ctx := context.Background()

	if err := c.Restore(ctx, "pw", "config.zip", []byte("x")); err == nil {
		t.Error("non-.tar must be rejected before any upload")
	}
	if err := c.Restore(ctx, "pw", "config.tar", nil); err == nil {
		t.Error("empty archive must be rejected")
	}
	if err := c.Restore(ctx, "pw", "config.tar", make([]byte, maxRestoreArchive+1)); err == nil {
		t.Error("archive above the AP's 2MB limit must be rejected")
	}
}
