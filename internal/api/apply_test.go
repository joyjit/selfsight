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

	"selfsight/internal/core"
)

// applyFake is a stateful fake WAX AP rich enough for the drift-apply flow:
// SSID slots (read/modify/create) and radio cores (read-modify-write), plus
// login/backup so the guarded pipeline can run.
type applyFake struct {
	mu         sync.Mutex
	ssidVLAN   int
	ssidPSK    string
	ssidAuth   int
	ssidHidden int
	ssidStatus int
	created    map[string]bool // slot -> created Guest ssid
	guestPSK   string          // what was written into the created slot
	guestVLAN  int
	guestAuth  int
	channels   map[string]string
	radioOn    map[string]string // band -> radioStatus "1"/"0"
}

func newApplyFake() *applyFake {
	return &applyFake{
		ssidVLAN: 5, ssidPSK: "old-pk", ssidAuth: 32, ssidStatus: 1,
		created: map[string]bool{}, guestPSK: "gk", guestVLAN: 20, guestAuth: 32,
		channels: map[string]string{"wlan0": "6", "wlan1": "36"},
		radioOn:  map[string]string{"wlan0": "1", "wlan1": "1"},
	}
}

func (ap *applyFake) core(band string) string {
	return fmt.Sprintf(`{"vapProfileStatus":%d,"ssid":"HomeNet","hideNetworkName":%d,"authenticationType":%d,"encryption":4,"presharedKey":%q,"vlanID":%d,"accessControlGroupNames":"x"}`,
		ap.ssidStatus, ap.ssidHidden, ap.ssidAuth, ap.ssidPSK, ap.ssidVLAN)
}

func (ap *applyFake) radioCore(band string) string {
	return fmt.Sprintf(`{"radioStatus":%q,"operateMode":"10","guardInterval":"1","txPower":"2","channel":%q,"channelWidth":"3","beamForming":"1"}`, ap.radioOn[band], ap.channels[band])
}

func (ap *applyFake) handle(w http.ResponseWriter, r *http.Request) {
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
		_, _ = io.WriteString(w, `{"status":0}`)
		return
	}
	switch {
	case strings.Contains(s, "adminPasswd"):
		_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
	case strings.Contains(s, "sysSerialNumber"):
		fmt.Fprintf(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9","operateMode":{"wlan0":"11ax","wlan1":"11ax"},"currentChannel":{"wlan0":%q,"wlan1":%q}},"basicSettings":{"apName":"AP","cloudStatus":"0"}}}`,
			ap.channels["wlan0"], ap.channels["wlan1"])
	case strings.Contains(s, "ssidGetDetails"):
		guest := ""
		if ap.created["SSID2"] {
			vap := fmt.Sprintf(`{"vap1":{"vapProfileStatus":1,"ssid":"Guest","hideNetworkName":0,"authenticationType":%d,"encryption":4,"presharedKey":%q,"vlanID":%d}}`,
				ap.guestAuth, ap.guestPSK, ap.guestVLAN)
			guest = fmt.Sprintf(`,"SSID2":{"band":"both","wlan0":%s,"wlan1":%s}`, vap, vap)
		}
		fmt.Fprintf(w, `{"status":0,"system":{"wlanSettings":{"wlanSettingTable":{"ssidGetDetails":{"SSID1":{"band":"both","wlan0":{"vap0":%s},"wlan1":{"vap0":%s}}%s}}}}}`,
			ap.core("wlan0"), ap.core("wlan1"), guest)
	case strings.Contains(s, "ssidGetFree"):
		_, _ = io.WriteString(w, `{"status":0,"system":{"wlanSettings":{"wlanSettingTable":{"ssidGetFree":{"SSID2":{"wlan0":"vap1","wlan1":"vap1"},"available":7}}}}}`)
	case strings.Contains(s, "ssidDelete"):
		var p struct {
			System struct {
				W struct {
					T struct {
						Del map[string]string `json:"ssidDelete"`
					} `json:"wlanSettingTable"`
				} `json:"wlanSettings"`
			} `json:"system"`
		}
		_ = json.Unmarshal(body, &p)
		for slot := range p.System.W.T.Del {
			delete(ap.created, slot)
		}
		_, _ = io.WriteString(w, `{"status":0}`)
	case strings.Contains(s, "ssidSetDetails"):
		var p struct {
			System struct {
				W struct {
					T struct {
						Set map[string]map[string]map[string]struct {
							SSID   string `json:"ssid"`
							VLAN   int    `json:"vlanID"`
							PSK    string `json:"presharedKey"`
							Auth   int    `json:"authenticationType"`
							Hidden int    `json:"hideNetworkName"`
							Status int    `json:"vapProfileStatus"`
						} `json:"ssidSetDetails"`
					} `json:"wlanSettingTable"`
				} `json:"wlanSettings"`
			} `json:"system"`
		}
		_ = json.Unmarshal(body, &p)
		for slot, bands := range p.System.W.T.Set {
			for _, vaps := range bands {
				for _, c := range vaps {
					if slot == "SSID1" {
						ap.ssidVLAN, ap.ssidPSK, ap.ssidAuth = c.VLAN, c.PSK, c.Auth
						ap.ssidHidden, ap.ssidStatus = c.Hidden, c.Status
					} else {
						ap.created[slot] = true
						ap.guestPSK, ap.guestVLAN, ap.guestAuth = c.PSK, c.VLAN, c.Auth
					}
				}
			}
		}
		_, _ = io.WriteString(w, `{"status":0}`)
	case strings.Contains(s, "maxWirelessClients"):
		fmt.Fprintf(w, `{"status":0,"system":{"wlanSettings":{"wlanSettingTable":{"wlan0":{"radioStatus":%q,"maxWirelessClients":"50"},"wlan1":{"radioStatus":%q,"maxWirelessClients":"50"}}}}}`,
			ap.radioOn["wlan0"], ap.radioOn["wlan1"])
	case strings.Contains(s, "guardInterval"):
		if strings.Contains(s, `"guardInterval":""`) { // read: empty leaves
			fmt.Fprintf(w, `{"status":0,"system":{"wlanSettings":{"wlanSettingTable":{"wlan0":%s,"wlan1":%s}}}}`,
				ap.radioCore("wlan0"), ap.radioCore("wlan1"))
			return
		}
		var p struct {
			System struct {
				W struct {
					T map[string]struct {
						Channel     string `json:"channel"`
						RadioStatus string `json:"radioStatus"`
					} `json:"wlanSettingTable"`
				} `json:"wlanSettings"`
			} `json:"system"`
		}
		_ = json.Unmarshal(body, &p)
		for band, v := range p.System.W.T {
			if v.Channel != "" {
				ap.channels[band] = v.Channel
			}
			if v.RadioStatus != "" {
				ap.radioOn[band] = v.RadioStatus
			}
		}
		_, _ = io.WriteString(w, `{"status":0}`)
	default:
		_, _ = io.WriteString(w, `{"status":1}`) // best-effort reads omitted
	}
}

func applyServer(t *testing.T, ap *applyFake, desired core.Desired) *Server {
	return applyServerSerial(t, ap, desired, "")
}

// applyServerSerial is applyServer with a recorded serial on the device entry
// (the fake AP always reports serial "S1").
func applyServerSerial(t *testing.T, ap *applyFake, desired core.Desired, serial string) *Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(ap.handle))
	t.Cleanup(ts.Close)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	host := strings.TrimPrefix(ts.URL, "https://")
	cfg := &core.Config{
		Server: core.Server{Listen: ":0"},
		Devices: []core.Device{{
			Name: "ap1", Host: host, Serial: serial, Username: "admin", Password: "pw", Desired: desired,
		}},
	}
	return New(cfg, nil, t.TempDir())
}

func TestApplyFixesDrift(t *testing.T) {
	ap := newApplyFake() // vlan 5, 5g channel 36
	s := applyServer(t, ap, core.Desired{
		SSIDs:  []core.SSID{{Name: "HomeNet", VLAN: 1, Security: "wpa2-psk"}},
		Radios: map[string]core.Radio{"5g": {Channel: "44"}},
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Results []struct {
			Change  string
			Applied bool
			Backup  string
		}
		Skipped []string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 {
		t.Fatalf("want 2 changes (ssid + radio), got %+v", got.Results)
	}
	for _, res := range got.Results {
		if !res.Applied || res.Backup == "" {
			t.Errorf("every change must be backed up and verified: %+v", res)
		}
	}
	if ap.ssidVLAN != 1 {
		t.Errorf("ssid vlan: want 1 written, device has %d", ap.ssidVLAN)
	}
	if ap.ssidPSK != "old-pk" {
		t.Errorf("undeclared passphrase must be carried forward, got %q", ap.ssidPSK)
	}
	if ap.channels["wlan1"] != "44" {
		t.Errorf("5g channel: want 44 written, device has %s", ap.channels["wlan1"])
	}
	if ap.channels["wlan0"] != "6" {
		t.Errorf("undeclared 2g channel must not change, device has %s", ap.channels["wlan0"])
	}

	// After a successful apply the device reads back in sync.
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/drift", nil))
	if !strings.Contains(rr.Body.String(), `"inSync":true`) {
		t.Errorf("post-apply drift should be in sync: %s", rr.Body.String())
	}
}

func TestApplyCreatesMissingSSID(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "Guest", VLAN: 20, Security: "wpa2-psk", Passphrase: "gk"}},
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !ap.created["SSID2"] {
		t.Error("missing declared SSID must be created in the free slot")
	}
}

func TestApplyRefusesToCreateWithoutPassphrase(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "Guest", VLAN: 20, Security: "wpa2-psk"}}, // no passphrase
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("creating a PSK network without a passphrase must fail, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "passphrase") {
		t.Errorf("error should tell the user what to declare: %s", rr.Body.String())
	}
	if ap.created["SSID2"] {
		t.Error("nothing may be written when the change is rejected")
	}
}

func boolPtr(b bool) *bool { return &b }

func TestApplyTogglesHiddenAndEnabled(t *testing.T) {
	ap := newApplyFake() // broadcast (hidden=0), enabled (status=1)
	s := applyServer(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "HomeNet", Hidden: boolPtr(true), Enabled: boolPtr(true)}},
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidHidden != 1 {
		t.Errorf("hidden must be written, device has hideNetworkName=%d", ap.ssidHidden)
	}
	if ap.ssidStatus != 1 {
		t.Errorf("enabled (in sync) must be carried forward as 1, device has vapProfileStatus=%d", ap.ssidStatus)
	}
	if ap.ssidVLAN != 5 || ap.ssidPSK != "old-pk" {
		t.Errorf("undeclared fields must not change: vlan=%d psk=%q", ap.ssidVLAN, ap.ssidPSK)
	}

	// After the apply the device reads back in sync.
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices/ap1/drift", nil))
	if !strings.Contains(rr.Body.String(), `"inSync":true`) {
		t.Errorf("post-apply drift should be in sync: %s", rr.Body.String())
	}
}

func TestApplyDisablesRadio(t *testing.T) {
	ap := newApplyFake() // both radios on
	s := applyServer(t, ap, core.Desired{
		Radios: map[string]core.Radio{"5g": {Enabled: boolPtr(false)}},
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.radioOn["wlan1"] != "0" {
		t.Errorf("5g radio must be written off, device has %q", ap.radioOn["wlan1"])
	}
	if ap.radioOn["wlan0"] != "1" {
		t.Errorf("undeclared 2g radio must stay on, device has %q", ap.radioOn["wlan0"])
	}
}

func TestDeleteSSIDEndpoint(t *testing.T) {
	ap := newApplyFake()
	ap.created["SSID2"] = true // the Guest network exists on the device
	s := applyServer(t, ap, core.Desired{})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/devices/ap1/ssids/Guest", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.created["SSID2"] {
		t.Error("SSID2 must be deleted from the device")
	}
	var got struct {
		Applied bool
		Backup  string
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Applied || got.Backup == "" {
		t.Errorf("delete must be backed up and read-back verified: %s", rr.Body.String())
	}
}

func TestDeleteSSIDRefusesPrimary(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{})

	// HomeNet lives in SSID1 — the device's primary network.
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/devices/ap1/ssids/HomeNet", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("deleting the primary SSID must be refused: %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "SSID1") {
		t.Errorf("error should say why: %s", rr.Body.String())
	}
}

func TestDeleteSSIDRefusesDeclared(t *testing.T) {
	ap := newApplyFake()
	ap.created["SSID2"] = true
	s := applyServer(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "Guest", VLAN: 20}}, // Guest is declared
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/devices/ap1/ssids/Guest", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("deleting a declared SSID must 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !ap.created["SSID2"] {
		t.Error("nothing may be deleted when the request is refused")
	}
}

func TestApplyRefusedOnSerialMismatch(t *testing.T) {
	// The entry records a different unit than the one now answering at the
	// host — apply must refuse before writing anything.
	ap := newApplyFake() // reports serial S1, vlan 5
	s := applyServerSerial(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "HomeNet", VLAN: 1, Security: "wpa2-psk"}},
	}, "OTHER-UNIT")

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("serial mismatch must 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "serial mismatch") {
		t.Errorf("error should name the problem: %s", rr.Body.String())
	}
	if ap.ssidVLAN != 5 {
		t.Errorf("nothing may be written on a serial mismatch, device has vlan %d", ap.ssidVLAN)
	}
}

func TestApplyProceedsOnSerialMatch(t *testing.T) {
	ap := newApplyFake()
	s := applyServerSerial(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "HomeNet", VLAN: 1, Security: "wpa2-psk"}},
	}, "S1") // matches the fake

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("matching serial must apply normally, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidVLAN != 1 {
		t.Errorf("apply should have written vlan 1, device has %d", ap.ssidVLAN)
	}
}

func TestSetNameRefusedOnSerialMismatch(t *testing.T) {
	// Covers the checkSerial path (handlers that don't otherwise read status).
	ap := newApplyFake()
	s := applyServerSerial(t, ap, core.Desired{}, "OTHER-UNIT")

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/config/name",
		strings.NewReader(`{"name":"NewName"}`)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("serial mismatch must 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "serial mismatch") {
		t.Errorf("error should name the problem: %s", rr.Body.String())
	}
}

func TestApplyNoOpWhenInSync(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{
		Radios: map[string]core.Radio{"5g": {Channel: "36"}}, // matches device
	})

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/apply", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"results":[]`) {
		t.Fatalf("in-sync apply must write nothing: %d %s", rr.Code, rr.Body.String())
	}
}
