package wax

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinTrustOnFirstUse(t *testing.T) {
	c := New("192.0.2.9", WithPinPath(t.TempDir()+"/pin.txt"))

	certA := []byte("certificate-A")
	certB := []byte("certificate-B")

	if err := c.verifyPin([][]byte{certA}, nil); err != nil {
		t.Fatalf("first contact must be trusted and recorded: %v", err)
	}
	if err := c.verifyPin([][]byte{certA}, nil); err != nil {
		t.Fatalf("same certificate must keep verifying: %v", err)
	}
	err := c.verifyPin([][]byte{certB}, nil)
	if err == nil {
		t.Fatal("a changed certificate must be rejected")
	}
	if !strings.Contains(err.Error(), "pin.txt") {
		t.Errorf("mismatch error must name the pin file so the user can re-trust: %v", err)
	}
	if err := c.verifyPin(nil, nil); err == nil {
		t.Error("no certificate at all must be rejected")
	}
}

func TestPinnedClientTalksTLS(t *testing.T) {
	// End to end through a real TLS handshake: a pinned client (its own
	// transport, not the test server's) must connect twice — the first
	// connection records the pin, the second verifies against it.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":0}`)
	}))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "https://")

	c := New(host, WithPinPath(t.TempDir()+"/pin.txt"))
	c.SetSession("tok", "sid")
	for i := 0; i < 2; i++ {
		if err := c.socket(context.Background(), `{}`, nil); err != nil {
			t.Fatalf("pinned connection %d failed: %v", i+1, err)
		}
	}
}

// A host names two cache files. Hashing it means no address — however odd, and
// whatever validation upstream may have missed — can steer one of those files
// out of its directory, and a fleet's addresses stay off the filesystem.
func TestCachePathsAreSafeAndStable(t *testing.T) {
	base := "/tmp/cache"
	hosts := []string{
		"192.0.2.20", "192.0.2.20:8443", "ap1.example.com",
		"../../etc/passwd", "a/b/c", "..", strings.Repeat("x", 300),
	}
	seen := map[string]string{}
	for _, host := range hosts {
		for _, p := range []string{PinPathIn(base, host), SessionPathIn(base, host)} {
			if filepath.Dir(p) != base {
				t.Errorf("host %q escaped the cache directory: %s", host, p)
			}
			if strings.Contains(p, host) && len(host) > 3 {
				t.Errorf("host %q should not appear in its cache path: %s", host, p)
			}
			if prev, dup := seen[p]; dup && prev != host {
				t.Errorf("hosts %q and %q share a cache file %s", prev, host, p)
			}
			seen[p] = host
		}
	}
	// Stable, so a device keeps its own cache across restarts. Held in
	// variables rather than compared inline: two identical calls side by side
	// read as a tautology (and staticcheck flags them as one), but the point
	// is that the path is derived from the host alone, with nothing random or
	// time-based mixed in.
	first := PinPathIn(base, "ap1")
	second := PinPathIn(base, "ap1")
	if first != second {
		t.Errorf("a host's cache path must not change between calls: %s then %s", first, second)
	}
	// A pin and a session are separate files.
	if PinPathIn(base, "ap1") == SessionPathIn(base, "ap1") {
		t.Error("pin and session must be separate files")
	}
}
