package wax

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A wireless write bounces the radio and the AP's web server drops
// connections for a while. The guarded apply must wait that out: verify
// retries on transport errors until the AP answers again, and only a
// definitive answer settles the result.
func TestApplyVerifyWaitsOutRadioBounce(t *testing.T) {
	var mu sync.Mutex
	verifyAttempts := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/AP_login":
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "sid"})
		case r.URL.Path == "/LogFile":
			_, _ = io.WriteString(w, `{"status":0}`)
		case r.URL.Path == "/wac510-backup":
			w.Header().Set("Content-Disposition", `attachment; filename="b.tar"`)
			_, _ = w.Write([]byte("archive"))
		case r.URL.Path == socketPath:
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "adminPasswd") {
				_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
				return
			}
			mu.Lock()
			verifyAttempts++
			n := verifyAttempts
			mu.Unlock()
			if n <= 2 {
				panic(http.ErrAbortHandler) // mid radio bounce: the connection just dies
			}
			_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9","operateMode":{"wlan0":"11ax","wlan1":"11ax"},"currentChannel":{"wlan0":"6","wlan1":"36"}},"basicSettings":{"apName":"AP","cloudStatus":"0"}}}`)
		}
	}))
	t.Cleanup(ts.Close)

	host := strings.TrimPrefix(ts.URL, "https://")
	m := NewManager(host, filepath.Join(t.TempDir(), "sess.json"), "admin", "pw",
		WithHTTPClient(ts.Client()))
	m.verifyPatience = 5 * time.Second
	m.verifyGap = 10 * time.Millisecond

	res, err := m.Apply(context.Background(), t.TempDir(), Change{
		Describe: "test change",
		Write:    func(ctx context.Context, c *Client) error { return nil },
		Verify: func(ctx context.Context, c *Client) (bool, string, error) {
			si, err := c.SystemInfo(ctx)
			if err != nil {
				return false, "", err
			}
			return si.Name == "AP", "apName=" + si.Name, nil
		},
	})
	if err != nil {
		t.Fatalf("apply must survive a radio bounce during verify: %v", err)
	}
	if !res.Applied {
		t.Errorf("verify should confirm once the AP answers again: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if verifyAttempts < 3 {
		t.Errorf("verify should have retried through the bounce, got %d attempts", verifyAttempts)
	}
}
