package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"selfsight/internal/core"
)

func postChange(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/devices/ap1/change", strings.NewReader(body))
	s.ServeHTTP(rr, req)
	return rr
}

// A one-off SSID toggle writes to the device without touching any config, and
// leaves the SSID's other fields exactly as the device had them.
func TestChangeHidesSSID(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{}) // nothing declared

	rr := postChange(t, s, `{"ssid":{"name":"HomeNet","hidden":true}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("change: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidHidden != 1 {
		t.Errorf("ssid not hidden on device: hideNetworkName=%d", ap.ssidHidden)
	}
	// Untouched fields keep their device values (read-modify-write, not a reset).
	if ap.ssidVLAN != 5 || ap.ssidPSK != "old-pk" {
		t.Errorf("one-off toggle clobbered other fields: vlan=%d psk=%q", ap.ssidVLAN, ap.ssidPSK)
	}
}

func TestChangeTurnsRadioOff(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{})

	rr := postChange(t, s, `{"radio":{"band":"5g","enabled":false}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("change: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.radioOn["wlan1"] != "0" {
		t.Errorf("5g radio still on: radioStatus=%q", ap.radioOn["wlan1"])
	}
	if ap.radioOn["wlan0"] != "1" {
		t.Errorf("2.4g radio was touched: radioStatus=%q", ap.radioOn["wlan0"])
	}
}

// A field declared in desired config is refused — the next apply would revert
// the one-off, so the two mechanisms must not fight.
func TestChangeRefusesDeclaredField(t *testing.T) {
	hidden := false
	s := applyServer(t, newApplyFake(), core.Desired{
		SSIDs: []core.SSID{{Name: "HomeNet", Hidden: &hidden}},
	})

	rr := postChange(t, s, `{"ssid":{"name":"HomeNet","hidden":true}}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("declared field: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	// The undeclared field on the same SSID is still fair game.
	rr = postChange(t, s, `{"ssid":{"name":"HomeNet","enabled":false}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("undeclared field: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestChangeRejectsBadBody(t *testing.T) {
	s := applyServer(t, newApplyFake(), core.Desired{})
	for _, body := range []string{
		`{}`, // neither
		`{"ssid":{"name":"HomeNet","hidden":true},"radio":{"band":"5g","enabled":false}}`, // both
		`{"ssid":{"name":"HomeNet"}}`,                                                // no field to change
		`{"radio":{"band":"9g","enabled":false}}`,                                    // unknown band
		`{"ssid":{"name":"HomeNet","passphrase":"short"}}`,                           // under 8 chars
		`{"ssid":{"name":"HomeNet","passphrase":"` + strings.Repeat("x", 64) + `"}}`, // over 63
		`{"ssid":{"name":"HomeNet","vlan":0}}`,                                       // vlan out of range
		`{"ssid":{"name":"HomeNet","vlan":5000}}`,                                    // vlan out of range
		`{"ssid":{"name":"HomeNet","security":"wep"}}`,                               // unsupported security
	} {
		if rr := postChange(t, s, body); rr.Code != http.StatusBadRequest {
			t.Errorf("body %s: want 400, got %d: %s", body, rr.Code, rr.Body.String())
		}
	}
}

// A one-off passphrase change writes the new key, keeps every other field, and
// is confirmed by reading the slot table back (the only read carrying the key).
func TestChangeSetsPassphrase(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{})

	rr := postChange(t, s, `{"ssid":{"name":"HomeNet","passphrase":"new-key-123"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("change: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidPSK != "new-key-123" {
		t.Errorf("passphrase not written: device has %q", ap.ssidPSK)
	}
	if ap.ssidVLAN != 5 || ap.ssidHidden != 0 || ap.ssidStatus != 1 {
		t.Errorf("other fields clobbered: vlan=%d hidden=%d status=%d", ap.ssidVLAN, ap.ssidHidden, ap.ssidStatus)
	}
	// The response must confirm the write without ever echoing the key.
	if !strings.Contains(rr.Body.String(), `"applied":true`) {
		t.Errorf("write not confirmed: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "new-key-123") {
		t.Errorf("response leaks the passphrase: %s", rr.Body.String())
	}
}

// One-off VLAN + security change on an existing SSID, verified by read-back.
func TestChangeSetsVlanAndSecurity(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{})

	rr := postChange(t, s,
		`{"ssid":{"name":"HomeNet","vlan":30,"security":"wpa3-sae","passphrase":"key-12345"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("change: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidVLAN != 30 || ap.ssidAuth != 64 || ap.ssidPSK != "key-12345" {
		t.Errorf("write incomplete: vlan=%d auth=%d psk=%q", ap.ssidVLAN, ap.ssidAuth, ap.ssidPSK)
	}
}

// A one-off change naming an SSID the device doesn't have creates it — the
// drawer's "add network" without declaring anything in config.yaml.
func TestChangeCreatesSSID(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{})

	rr := postChange(t, s,
		`{"ssid":{"name":"Guest","security":"wpa2-psk","passphrase":"guest-key-1","vlan":20}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("change: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !ap.created["SSID2"] {
		t.Fatal("SSID must be created in the free slot")
	}
	if ap.guestPSK != "guest-key-1" || ap.guestVLAN != 20 {
		t.Errorf("created with wrong values: psk=%q vlan=%d", ap.guestPSK, ap.guestVLAN)
	}
}

func TestChangeRefusesDeclaredVlan(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "HomeNet", VLAN: 5}},
	})

	rr := postChange(t, s, `{"ssid":{"name":"HomeNet","vlan":30}}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("declared vlan: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidVLAN != 5 {
		t.Errorf("nothing may be written when refused, device has vlan %d", ap.ssidVLAN)
	}
}

func TestChangeRefusesDeclaredPassphrase(t *testing.T) {
	ap := newApplyFake()
	s := applyServer(t, ap, core.Desired{
		SSIDs: []core.SSID{{Name: "HomeNet", Passphrase: "declared-key"}},
	})

	rr := postChange(t, s, `{"ssid":{"name":"HomeNet","passphrase":"new-key-123"}}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("declared passphrase: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if ap.ssidPSK != "old-pk" {
		t.Errorf("nothing may be written when refused, device has %q", ap.ssidPSK)
	}
}

// Setting a key on an open network is refused before anything is written —
// the passphrase would be dead weight until the SSID gets a security mode.
func TestChangeRefusesPassphraseOnOpenSSID(t *testing.T) {
	ap := newApplyFake()
	ap.ssidAuth = 0 // HomeNet is an open network
	s := applyServer(t, ap, core.Desired{})

	rr := postChange(t, s, `{"ssid":{"name":"HomeNet","passphrase":"new-key-123"}}`)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("open ssid: want 502, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "open") {
		t.Errorf("error should say why: %s", rr.Body.String())
	}
	if ap.ssidPSK != "old-pk" {
		t.Errorf("nothing may be written when refused, device has %q", ap.ssidPSK)
	}
}
