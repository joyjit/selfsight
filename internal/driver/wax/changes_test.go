package wax

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"selfsight/internal/core"
)

// chanAP is a fake AP that separates the CONFIG channel (what a write stores)
// from the OPERATING channel (monitor.currentChannel). When retune is false it
// models a device that accepts a channel into config but never actually moves
// the radio — the exact case that made selfsight report a false success.
type chanAP struct {
	config     map[string]string // wlan -> configured channel
	operating  map[string]string // wlan -> operating channel
	configW    map[string]string // wlan -> configured width code ("" defaults to "3")
	operatingW map[string]string // wlan -> operating width label
	retune     bool              // does a write move the operating channel too?
}

// widthCodeToLabel is how this fake models a width write taking effect on the
// radio (narrowing always works, so operating follows config). Codes match the
// live WAX610: "0"=20 MHz, "1"=40 MHz, "2"/"3"=20/40 MHz.
var widthCodeToLabel = map[string]string{"0": "20 MHz", "1": "40 MHz", "2": "20/40 MHz", "3": "20/40 MHz"}

// cw returns the configured width code for a band, defaulting to "3" (widest).
func (ap *chanAP) cw(wl string) string {
	if v := ap.configW[wl]; v != "" {
		return v
	}
	return "3"
}

func (ap *chanAP) server(t *testing.T) *httptest.Server {
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
		s := string(body)
		switch {
		case r.URL.Path == "/LogFile":
			_, _ = io.WriteString(w, `{"status":0}`)
		case strings.Contains(s, "adminPasswd"):
			_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
		case strings.Contains(s, "currentChannel"): // SystemInfo (operating)
			_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9","operateMode":{"wlan0":"11ax","wlan1":"11ax"},"currentChannel":{"wlan0":`+
				jsonStr(ap.operating["wlan0"])+`,"wlan1":`+jsonStr(ap.operating["wlan1"])+`},"channelWidth":{"wlan0":`+
				jsonStr(ap.operatingW["wlan0"])+`,"wlan1":`+jsonStr(ap.operatingW["wlan1"])+`}},"basicSettings":{"apName":"AP","cloudStatus":"0"}}}`)
		case strings.Contains(s, `"channel":""`): // radio-core read (config)
			_, _ = io.WriteString(w, `{"status":0,"system":{"wlanSettings":{"wlanSettingTable":{`+
				`"wlan0":{"radioStatus":"1","operateMode":"10","guardInterval":"1","txPower":"2","channel":`+jsonStr(ap.config["wlan0"])+`,"channelWidth":`+jsonStr(ap.cw("wlan0"))+`,"beamForming":"1"},`+
				`"wlan1":{"radioStatus":"1","operateMode":"10","guardInterval":"1","txPower":"2","channel":`+jsonStr(ap.config["wlan1"])+`,"channelWidth":`+jsonStr(ap.cw("wlan1"))+`,"beamForming":"1"}}}}}`)
		default: // radio write: stores into config, moves the radio only if retune
			var p struct {
				System struct {
					WlanSettings struct {
						Table map[string]RadioWrite `json:"wlanSettingTable"`
					} `json:"wlanSettings"`
				} `json:"system"`
			}
			_ = json.Unmarshal(body, &p)
			for band, rw := range p.System.WlanSettings.Table {
				if rw.Channel != "" {
					ap.config[band] = rw.Channel
					if ap.retune {
						ap.operating[band] = rw.Channel
					}
				}
				// A read-modify-write always carries channelWidth back; only the
				// width-aware fakes (non-nil maps) track it.
				if rw.ChannelWidth != "" && ap.configW != nil {
					ap.configW[band] = rw.ChannelWidth
					// Narrowing/widening always takes effect on the radio.
					ap.operatingW[band] = widthCodeToLabel[rw.ChannelWidth]
				}
			}
			_, _ = io.WriteString(w, `{"status":0}`)
		}
	}))
}

func chanManager(t *testing.T, ap *chanAP) *Manager {
	t.Helper()
	// Poll fast so the "radio never moves" case doesn't wait a real minute.
	old, oldp := channelSettle, channelPoll
	channelSettle, channelPoll = 150*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { channelSettle, channelPoll = old, oldp })
	ts := ap.server(t)
	t.Cleanup(ts.Close)
	host := strings.TrimPrefix(ts.URL, "https://")
	return NewManager(host, t.TempDir()+"/sess.json", "admin", "pw", WithHTTPClient(ts.Client()))
}

// The write is applied only when the radio actually ends up operating on the
// requested channel.
func TestApplyRadiosConfirmsOperatingChannel(t *testing.T) {
	ap := &chanAP{
		config:    map[string]string{"wlan0": "1", "wlan1": "36"},
		operating: map[string]string{"wlan0": "1", "wlan1": "36"},
		retune:    true,
	}
	mgr := chanManager(t, ap)
	res, err := mgr.ApplyRadios(context.Background(), t.TempDir(),
		map[string]core.Radio{"2g": {Channel: "6"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied || !strings.Contains(res.Observed, "wlan0=ch 6") {
		t.Fatalf("radio that re-tuned must be applied: %+v", res)
	}
}

// The core regression: the device stores the channel in config but the radio
// stays put (it can't run that channel). selfsight must NOT report success, and
// the observed value must show the real operating channel.
func TestApplyRadiosRejectsConfigOnlyChannel(t *testing.T) {
	ap := &chanAP{
		config:    map[string]string{"wlan0": "1", "wlan1": "36"},
		operating: map[string]string{"wlan0": "1", "wlan1": "36"},
		retune:    false, // config accepts it; the radio never moves
	}
	mgr := chanManager(t, ap)
	res, err := mgr.ApplyRadios(context.Background(), t.TempDir(),
		map[string]core.Radio{"2g": {Channel: "11"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied {
		t.Errorf("a channel that only reached config, not the radio, must not be 'applied': %+v", res)
	}
	if ap.config["wlan0"] != "11" {
		t.Errorf("config should still have received the write: %v", ap.config)
	}
	if !strings.Contains(res.Observed, "wlan0=ch 1") {
		t.Errorf("observed must report the real operating channel (1): %q", res.Observed)
	}
}

// Narrowing to 20 MHz alongside the channel change is the "one-click fix" for
// 2.4 GHz crowding: the width code is written and confirmed against the
// operating width label, and channel 11 (which the radio refuses at 40 MHz)
// now takes because the radio is narrow.
func TestApplyRadiosNarrowsWidth(t *testing.T) {
	ap := &chanAP{
		config:     map[string]string{"wlan0": "1", "wlan1": "36"},
		operating:  map[string]string{"wlan0": "1", "wlan1": "36"},
		configW:    map[string]string{"wlan0": "3", "wlan1": "3"},
		operatingW: map[string]string{"wlan0": "20/40 MHz", "wlan1": "20/40/80 MHz"},
		retune:     true,
	}
	mgr := chanManager(t, ap)
	res, err := mgr.ApplyRadios(context.Background(), t.TempDir(),
		map[string]core.Radio{"2g": {Channel: "11", Width: "20"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatalf("narrow-to-20 + channel 11 should apply: %+v", res)
	}
	if ap.configW["wlan0"] != "0" {
		t.Errorf("20 MHz must be written as width code 0: %v", ap.configW)
	}
	if !strings.Contains(res.Observed, "wlan0=20 MHz") {
		t.Errorf("observed must confirm the 20 MHz operating width: %q", res.Observed)
	}
	if !strings.Contains(res.Observed, "wlan0=ch 11") {
		t.Errorf("observed must confirm channel 11: %q", res.Observed)
	}
}

// An unsupported width is refused before any write.
func TestApplyRadiosRejectsBadWidth(t *testing.T) {
	ap := &chanAP{
		config:     map[string]string{"wlan0": "1", "wlan1": "36"},
		operating:  map[string]string{"wlan0": "1", "wlan1": "36"},
		configW:    map[string]string{"wlan0": "3", "wlan1": "3"},
		operatingW: map[string]string{"wlan0": "20/40 MHz", "wlan1": "20/40/80 MHz"},
	}
	mgr := chanManager(t, ap)
	_, err := mgr.ApplyRadios(context.Background(), t.TempDir(),
		map[string]core.Radio{"2g": {Width: "160"}})
	if err == nil {
		t.Fatal("width 160 must be rejected")
	}
}
