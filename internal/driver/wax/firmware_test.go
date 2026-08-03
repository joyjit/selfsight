package wax

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckFirmware(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == "/LogFile": // method 5 cloud check
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(string(body), "ImageAvailable"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"FwUpdate":{"ImageAvailable":"1","ImageVersion":"V13.0.0.1","LastcheckedDate":"today","releasenotesurl":"https://x"}}}`)
		default:
			_, _ = io.WriteString(w, `{"status":1}`)
		}
	}))
	defer ts.Close()
	c := New(strings.TrimPrefix(ts.URL, "https://"), WithHTTPClient(ts.Client()))
	c.SetSession("tok", "sid")

	fw, err := c.CheckFirmware(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !fw.UpdateAvailable || fw.AvailableImage != "V13.0.0.1" {
		t.Errorf("firmware = %+v", fw)
	}
}

func TestUpgradePollLoop(t *testing.T) {
	var polls atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		switch {
		case strings.Contains(s, `"method":7`): // start
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(s, `"fwPercent":0`): // download phase
			n := polls.Add(1)
			pct := "50"
			if n >= 2 {
				pct = "100"
			}
			_, _ = io.WriteString(w, `{"status":0,"percent":`+pct+`}`)
		case strings.Contains(s, `"fwPercent":1`): // flash phase; done when status=100
			_, _ = io.WriteString(w, `{"status":100,"percent":100}`)
		default:
			_, _ = io.WriteString(w, `{"status":0}`)
		}
	}))
	defer ts.Close()
	c := New(strings.TrimPrefix(ts.URL, "https://"), WithHTTPClient(ts.Client()))
	c.SetSession("tok", "sid")
	c.pollInterval = time.Millisecond // don't wait 5s per poll in the test

	var lastPhase string
	var done bool
	if err := c.Upgrade(context.Background(), func(p UpgradeProgress) {
		lastPhase = p.Phase
		if p.Done {
			done = true
		}
	}); err != nil {
		t.Fatal(err)
	}
	if lastPhase != "flash" || !done {
		t.Errorf("upgrade did not complete cleanly: phase=%s done=%v", lastPhase, done)
	}
}
