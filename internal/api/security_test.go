package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"selfsight/internal/core"
)

// login returns a valid session cookie for a server whose config has auth on.
func login(t *testing.T, s *Server, password string) *http.Cookie {
	t.Helper()
	rr := do(s, http.MethodPost, "/api/auth/login", fmt.Sprintf(`{"password":%q}`, password))
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("login set no session cookie")
	return nil
}

// A hostile page can make the browser send a request with the session cookie
// attached. It cannot set a custom header or a JSON content type on that
// request, so a change that carries neither is refused.
func TestCrossSiteWriteIsRefused(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())

	forged := httptest.NewRequest(http.MethodPost, "/api/devices/living-room/apply", nil)
	forged.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, forged)
	if rr.Code != http.StatusForbidden {
		t.Errorf("a form-style cross-site POST must be refused, got %d", rr.Code)
	}

	// Reading is always safe, so it is not gated.
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/devices", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("a read must not be refused, got %d", rr.Code)
	}
}

// An Origin naming another site is refused outright, even when the request
// otherwise looks like the dashboard's own.
func TestForeignOriginIsRefused(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())

	req := apiRequest(http.MethodPost, "/api/devices/living-room/apply", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("a write from a foreign origin must be refused, got %d", rr.Code)
	}

	// The dashboard's own origin passes the gate. Aimed at a device that does
	// not exist, so the request stops at the router rather than dialing an AP.
	req = apiRequest(http.MethodPost, "/api/devices/nope/apply", nil)
	req.Header.Set("Origin", "http://"+req.Host)
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Errorf("a write from our own origin must pass the gate: %s", rr.Body.String())
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	// Both an API response and the dashboard's own files.
	for _, path := range []string{"/api/devices", "/"} {
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		for h, v := range want {
			if got := rr.Header().Get(h); got != v {
				t.Errorf("%s: %s = %q, want %q", path, h, got, v)
			}
		}
		if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: weak or missing content security policy: %q", path, csp)
		}
	}
}

// Guessing has to become useless quickly, and the lockout must not depend on
// the attacker sending anything in particular.
func TestLoginRateLimit(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())

	for i := 0; i < loginMaxFailures; i++ {
		if rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"wrong"}`); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, rr.Code)
		}
	}
	rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"wrong"}`)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: want 429, got %d", loginMaxFailures, rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("a lockout must say how long it lasts")
	}
	// The right password is refused too — otherwise the limit would only slow
	// down a guesser who never guesses right.
	if rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"hunter2"}`); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("a locked-out address stays locked out: got %d", rr.Code)
	}
}

// A success inside the window clears the count, so a person who mistypes a few
// times and then gets it right is not left one slip from a lockout.
func TestLoginFailuresClearedOnSuccess(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())
	for i := 0; i < loginMaxFailures-1; i++ {
		do(s, http.MethodPost, "/api/auth/login", `{"password":"wrong"}`)
	}
	login(t, s, "hunter2")
	for i := 0; i < loginMaxFailures-1; i++ {
		if rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"wrong"}`); rr.Code != http.StatusUnauthorized {
			t.Fatalf("the budget should have been reset, got %d on attempt %d", rr.Code, i+1)
		}
	}
}

// Rotating the password has to evict whoever is already logged in, or the
// rotation protects nothing.
func TestPasswordChangeLogsEveryoneOut(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())
	ck := login(t, s, "hunter2")
	if rr := do(s, http.MethodGet, "/api/devices", "", ck); rr.Code != http.StatusOK {
		t.Fatalf("session should work before the change, got %d", rr.Code)
	}

	rotated := authedConfig()
	rotated.Server.Auth = &core.Auth{Password: "hunter3"}
	s.swapConfig(rotated)

	if rr := do(s, http.MethodGet, "/api/devices", "", ck); rr.Code != http.StatusUnauthorized {
		t.Fatalf("the old session must not survive a password change, got %d", rr.Code)
	}
}

// Turning auth on must not leave sessions minted while it was off in place.
func TestTurningAuthOnClearsSessions(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())
	ck := login(t, s, "hunter2")

	s.swapConfig(testConfig()) // auth off — everything is open
	s.swapConfig(authedConfig())

	if rr := do(s, http.MethodGet, "/api/devices", "", ck); rr.Code != http.StatusUnauthorized {
		t.Fatalf("a session from before must not survive, got %d", rr.Code)
	}
}

// An unrelated edit (adding a device, say) must not throw everyone out.
func TestDeviceEditKeepsSessions(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())
	ck := login(t, s, "hunter2")

	cfg := authedConfig()
	cfg.Devices = append(cfg.Devices, core.Device{
		Name: "garage", Host: "192.0.2.30", Username: "admin", Password: "pw",
	})
	s.swapConfig(cfg)

	if rr := do(s, http.MethodGet, "/api/devices", "", ck); rr.Code != http.StatusOK {
		t.Fatalf("an unrelated config change must not log anyone out, got %d", rr.Code)
	}
}

// The router cleans paths before matching, so the gate has to clean them too —
// otherwise "/api/auth/../devices" would look open here and still be routed to
// the devices handler.
func TestAuthGateResistsPathTricks(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())
	for _, path := range []string{
		"/api/auth/../devices",
		"/api/healthz/../devices",
		"/api/auth/status/../../devices",
	} {
		if rr := do(s, http.MethodGet, path, ""); rr.Code != http.StatusUnauthorized {
			t.Errorf("%s must not slip past the login gate, got %d", path, rr.Code)
		}
	}
}

// selfsight writes to one access point at a time. The server enforces that
// itself rather than trusting callers to take turns.
func TestFleetWriteLockIsExclusive(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())

	if busy, ok := s.claimFleetWrite("living-room"); !ok {
		t.Fatalf("the first claim must succeed, blocked by %q", busy)
	}
	busy, ok := s.claimFleetWrite("garage")
	if ok {
		t.Fatal("a second device must not be written to at the same time")
	}
	if busy != "living-room" {
		t.Errorf("the refusal should name the holder, got %q", busy)
	}

	// A stale release from another device must not free this claim.
	s.releaseFleetWrite("garage")
	if _, ok := s.claimFleetWrite("garage"); ok {
		t.Fatal("releasing under the wrong name must not free the slot")
	}

	s.releaseFleetWrite("living-room")
	if _, ok := s.claimFleetWrite("garage"); !ok {
		t.Error("the slot must be free once its holder releases it")
	}
}

// A write in progress is reported to the caller as a conflict, not queued
// silently or run in parallel.
func TestWriteWhileFleetBusyIsRefused(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())
	if _, ok := s.claimFleetWrite("garage"); !ok {
		t.Fatal("claim failed")
	}
	defer s.releaseFleetWrite("garage")

	rr := doReq(t, s, http.MethodPost, "/api/devices/living-room/apply", "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409 while the fleet is busy, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "garage") {
		t.Errorf("the refusal should say which device is being written to: %s", rr.Body.String())
	}
}

// The edit form needs to know a passphrase is stored so it can offer "leave
// blank to keep" — it must never be sent the passphrase itself.
func TestDeviceConfigReportsPassphraseWithoutSendingIt(t *testing.T) {
	cfg := testConfig()
	cfg.Devices[0].Desired = core.Desired{SSIDs: []core.SSID{
		{Name: "HomeNet", Security: "wpa2-psk", Passphrase: "super-secret-key"},
		{Name: "Open", Security: "open"},
	}}
	s := New(cfg, nil, t.TempDir())

	rr := doReq(t, s, http.MethodGet, "/api/devices/living-room/config", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "super-secret-key") {
		t.Fatalf("the config endpoint leaked a passphrase: %s", body)
	}
	if !strings.Contains(body, `"hasPassphrase":true`) {
		t.Errorf("a declared passphrase should be reported as present: %s", body)
	}
	if strings.Count(body, `"hasPassphrase":true`) != 1 {
		t.Errorf("only the network that has one should report it: %s", body)
	}
}

// The add-device test dials whatever address it is handed, so it holds that
// address to the same rules a configured one has to pass.
func TestTestConnectionRejectsBadHost(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())
	for _, host := range []string{"../../etc/passwd", "a b", "192.0.2.20:99999"} {
		rr := doReq(t, s, http.MethodPost, "/api/devices/test",
			`{"host":"`+host+`","username":"admin","password":"pw"}`)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("host %q should be refused, got %d: %s", host, rr.Code, rr.Body.String())
		}
	}
}
