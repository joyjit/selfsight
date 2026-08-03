package wax

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
