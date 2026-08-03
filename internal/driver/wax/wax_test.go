package wax

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAP replays the sanitized fixtures under testdata/wax610. It routes an
// incoming /socketCommunication request to the fixture whose request.json
// matches (canonically), and requires the warm-jar `security` header + ssid
// cookie — so the driver's signing is exercised, not just its parsing.
type fakeAP struct {
	byRequest map[string][]byte // canonical request JSON -> response body
}

func newFakeAP(t *testing.T) *fakeAP {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "testdata", "wax610")
	reqs, err := filepath.Glob(filepath.Join(dir, "*.request.json"))
	if err != nil || len(reqs) == 0 {
		t.Fatalf("no fixtures under %s: %v", dir, err)
	}
	ap := &fakeAP{byRequest: map[string][]byte{}}
	for _, rq := range reqs {
		resp := strings.TrimSuffix(rq, ".request.json") + ".response.json"
		rb, err := os.ReadFile(rq)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := os.ReadFile(resp)
		if err != nil {
			t.Fatalf("fixture %s has no response: %v", rq, err)
		}
		ap.byRequest[canonical(t, rb)] = sb
	}
	return ap
}

func (ap *fakeAP) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Login bootstrap: the GET seeds the lighttpd session cookie.
		if r.Method == http.MethodGet && r.URL.Path == "/AP_login" {
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed-sid", HttpOnly: true})
			return
		}
		if r.URL.Path != socketPath {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)

		// Login POST: credentials present. Require the GET-seeded cookie, mirror
		// the device by returning a token (the client already holds the cookie).
		if strings.Contains(string(body), "adminPasswd") {
			if !strings.Contains(r.Header.Get("Cookie"), "lhttpdsid=seed-sid") {
				_, _ = io.WriteString(w, `{"status":100}`) // cold login (no bootstrap) -> locked
				return
			}
			_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"test-token"}}`)
			return
		}

		// Read: require a signed warm-jar request; unsigned -> auth-dead status.
		if r.Header.Get("security") == "" || !strings.Contains(r.Header.Get("Cookie"), "ssid=") {
			_, _ = io.WriteString(w, `{"status":401}`)
			return
		}
		resp, ok := ap.byRequest[canonical(t, body)]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"status":1}`)
			return
		}
		_, _ = w.Write(resp)
	}))
}

func canonical(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("bad JSON fixture/request: %v", err)
	}
	out, _ := json.Marshal(v) // map keys are sorted by encoding/json
	return string(out)
}

func newTestClient(t *testing.T, ap *fakeAP) *Client {
	t.Helper()
	ts := ap.server(t)
	t.Cleanup(ts.Close)
	host := strings.TrimPrefix(ts.URL, "https://")
	c := New(host, WithHTTPClient(ts.Client()))
	c.SetSession("test-token", "test-lhttpdsid")
	return c
}

func TestSystemInfo(t *testing.T) {
	c := newTestClient(t, newFakeAP(t))
	si, err := c.SystemInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if si.Name != "LivingRoomAP" || si.Serial != "SERIAL0000001" {
		t.Errorf("identity wrong: %+v", si)
	}
	if si.MAC != "AA-BB-CC-B5-24-9F" || si.Firmware != "V12.8.0.7" {
		t.Errorf("mac/fw wrong: %+v", si)
	}
	if si.IP != "192.0.2.183" || si.Gateway != "192.0.2.1" || !si.GatewayUp {
		t.Errorf("network wrong: %+v", si)
	}
	if !si.Standalone || si.Devices != 5 {
		t.Errorf("standalone/devices wrong: %+v", si)
	}
	if si.FQDN != "livingroomap.example.com" {
		t.Errorf("fqdn wrong: %q", si.FQDN)
	}
	if len(si.Radios) != 2 {
		t.Fatalf("want 2 radios, got %d", len(si.Radios))
	}
	r24 := si.Radios[0]
	if r24.Band != "2.4 GHz" || r24.Mode != "11ax" || r24.Channel != "1" || r24.Stations != 3 {
		t.Errorf("2.4GHz radio wrong: %+v", r24)
	}
	// Airtime split: total 50%, ours 7%, neighbours (OBSS) 43%.
	if r24.ChannelUtil != "50" || r24.SelfUtil != "7" || r24.ObssUtil != "43" {
		t.Errorf("2.4GHz utilization split wrong: %+v", r24)
	}
	if si.Radios[1].Band != "5 GHz" || si.Radios[1].Channel != "52" || si.Radios[1].Stations != 2 {
		t.Errorf("5GHz radio wrong: %+v", si.Radios[1])
	}
}

func TestRadioSettings(t *testing.T) {
	c := newTestClient(t, newFakeAP(t))
	rs, err := c.RadioSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("want 2 bands, got %d", len(rs))
	}
	for _, r := range rs {
		if !r.On || r.MaxClients != 200 {
			t.Errorf("radio setting wrong: %+v", r)
		}
	}
}

func TestSSIDs(t *testing.T) {
	c := newTestClient(t, newFakeAP(t))
	ssids, err := c.SSIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ssids) != 1 {
		t.Fatalf("want 1 ssid, got %d: %+v", len(ssids), ssids)
	}
	s := ssids[0]
	if s.Name != "example.com" || s.VLAN != 1 || s.Hidden {
		t.Errorf("ssid wrong: %+v", s)
	}
	if !s.Enabled {
		t.Errorf("fixture SSID has vapProfileStatus 1, must read enabled: %+v", s)
	}
	if s.Security != "WPA2-PSK/AES" {
		t.Errorf("security label wrong: %q", s.Security)
	}
	if len(s.Bands) != 2 {
		t.Errorf("want both bands, got %v", s.Bands)
	}
}

func TestClients(t *testing.T) {
	c := newTestClient(t, newFakeAP(t))
	cl, err := c.Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cl.Total != 5 {
		t.Errorf("total wrong: %d", cl.Total)
	}
	if len(cl.PerSSID) != 2 {
		t.Fatalf("want 2 per-ssid rows, got %+v", cl.PerSSID)
	}
	var sum int
	for _, p := range cl.PerSSID {
		if p.SSID != "example.com" {
			t.Errorf("ssid name wrong: %+v", p)
		}
		sum += p.Count
	}
	if sum != 5 {
		t.Errorf("per-ssid counts sum wrong: %d", sum)
	}
}

func TestClientList(t *testing.T) {
	c := newTestClient(t, newFakeAP(t))
	cl, err := c.ClientList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cl) != 2 {
		t.Fatalf("want 2 clients, got %+v", cl)
	}
	first := cl[0]
	if first.Hostname != "living-laptop" || first.IP != "192.0.2.126" || first.Band != "5 GHz" {
		t.Errorf("client 0 wrong: %+v", first)
	}
	if first.OS != "Generic Linux" || first.VLAN != 1 || first.SSID != "example.com" {
		t.Errorf("client 0 fields wrong: %+v", first)
	}
	// The second client reported no hostname, so it falls back to its MAC.
	if cl[1].Hostname != cl[1].MAC {
		t.Errorf("client 1 hostname should mirror MAC: %+v", cl[1])
	}
}

func TestFirmware(t *testing.T) {
	c := newTestClient(t, newFakeAP(t))
	fw, err := c.Firmware(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fw.UpdateAvailable {
		t.Errorf("expected no update available: %+v", fw)
	}
	if fw.LastChecked == "" {
		t.Errorf("expected a last-checked date")
	}
}

func TestLoginThenRead(t *testing.T) {
	ap := newFakeAP(t)
	ts := ap.server(t)
	t.Cleanup(ts.Close)
	host := strings.TrimPrefix(ts.URL, "https://")
	c := New(host, WithHTTPClient(ts.Client())) // no session yet

	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	sess := c.Session()
	if sess.Token != "test-token" || sess.LHTTPDSID != "seed-sid" {
		t.Fatalf("login produced wrong session: %+v", sess)
	}
	// The session from login must be able to read.
	if _, err := c.SystemInfo(context.Background()); err != nil {
		t.Fatalf("read after login failed: %v", err)
	}
}

func TestUnauthenticatedIsAuthExpired(t *testing.T) {
	ap := newFakeAP(t)
	ts := ap.server(t)
	t.Cleanup(ts.Close)
	host := strings.TrimPrefix(ts.URL, "https://")
	c := New(host, WithHTTPClient(ts.Client())) // no SetSession
	_, err := c.SystemInfo(context.Background())
	if !errors.Is(err, ErrAuthExpired) {
		t.Fatalf("want ErrAuthExpired without a session, got %v", err)
	}
}

func TestStatusMapping(t *testing.T) {
	cases := map[int]error{0: nil, 1: ErrBadRequest, 100: ErrManaged, 401: ErrAuthExpired}
	for code, want := range cases {
		if got := apiStatus(code).err(); !errors.Is(got, want) {
			t.Errorf("status %d -> %v, want %v", code, got, want)
		}
	}
	var ae *APIError
	if got := apiStatus(7).err(); !errors.As(got, &ae) || ae.Status != 7 {
		t.Errorf("status 7 -> %v, want APIError{7}", got)
	}
}

// The APs reject requests whose Host header is a DNS name (status 1) and
// their certificates name no hosts — so a name in config must be resolved and
// the request sent to the IP. The fake AP checks what host it was dialed with.
func TestDNSNameIsDialedByIP(t *testing.T) {
	var gotHost string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = io.WriteString(w, `{"status":0}`)
	}))
	t.Cleanup(ts.Close)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	c := New("localhost:"+port, WithHTTPClient(ts.Client()))
	c.SetSession("tok", "sid")
	if err := c.socket(context.Background(), `{}`, nil); err != nil {
		t.Fatalf("read via DNS name: %v", err)
	}
	if !strings.HasPrefix(gotHost, "127.0.0.1:") {
		t.Errorf("request went to host %q — a DNS name must be resolved and dialed by IP", gotHost)
	}
}

// IPs (with or without port) pass through dialAddr untouched; only names hit
// the resolver.
func TestDialAddrKeepsIPs(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.80":      "192.0.2.80",
		"192.0.2.80:8443": "192.0.2.80:8443",
		"fe80::1":         "[fe80::1]",
	} {
		got, err := dialAddr(context.Background(), in)
		if err != nil {
			t.Errorf("dialAddr(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("dialAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// The AP stores an unset FQDN as the literal "0"; that sentinel must never
// reach callers as if it were a name they could dial.
func TestUnsetFQDN(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0", ""},
		{"", ""},
		{"ap.example.com", "ap.example.com"},
		{"  ap.example.com  ", "ap.example.com"},
		{"10", "10"}, // only an exact "0" is the sentinel
	} {
		if got := unsetFQDN(tc.in); got != tc.want {
			t.Errorf("unsetFQDN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
