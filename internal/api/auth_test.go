package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"selfsight/internal/core"
)

func authedConfig() *core.Config {
	cfg := testConfig()
	cfg.Server.Auth = &core.Auth{Password: "hunter2"}
	return cfg
}

func do(s *Server, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := apiRequest(method, path, strings.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	s.ServeHTTP(rr, req)
	return rr
}

func TestAuthGatesTheAPI(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())

	if rr := do(s, http.MethodGet, "/api/devices", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/devices: want 401, got %d", rr.Code)
	}
	// Open paths keep working without a login.
	if rr := do(s, http.MethodGet, "/api/healthz", ""); rr.Code != http.StatusOK {
		t.Errorf("healthz must stay open, got %d", rr.Code)
	}
	if rr := do(s, http.MethodGet, "/api/auth/status", ""); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Body.String(), `"required":true`) {
		t.Errorf("auth status must be open and report required: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodGet, "/", ""); rr.Code != http.StatusOK {
		t.Errorf("the SPA must load so it can show the login form, got %d", rr.Code)
	}
}

func TestSessionCookieSecureOverHTTPS(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())

	sessionOf := func(rr *httptest.ResponseRecorder) *http.Cookie {
		for _, c := range rr.Result().Cookies() {
			if c.Name == sessionCookie {
				return c
			}
		}
		t.Fatal("no session cookie set")
		return nil
	}

	// Plain HTTP (no proxy): the cookie must NOT be Secure, or the browser
	// would drop it and every login on a LAN deployment would silently fail.
	rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"hunter2"}`)
	if c := sessionOf(rr); c.Secure {
		t.Error("cookie must not be Secure over plain HTTP")
	}

	// Behind a TLS-terminating proxy/tunnel: standard X-Forwarded-Proto signal
	// → Secure, so the browser never sends the session over plaintext.
	req := apiRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"hunter2"}`))
	req.Header.Set("X-Forwarded-Proto", "https")
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if c := sessionOf(rr); !c.Secure {
		t.Error("cookie must be Secure when the request arrived over HTTPS")
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	s := New(authedConfig(), nil, t.TempDir())

	if rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"wrong"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: want 401, got %d", rr.Code)
	}

	rr := do(s, http.MethodPost, "/api/auth/login", `{"password":"hunter2"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("login: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var ck *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			ck = c
		}
	}
	if ck == nil || ck.Value == "" || !ck.HttpOnly {
		t.Fatalf("login must set an HttpOnly session cookie, got %+v", ck)
	}

	if rr := do(s, http.MethodGet, "/api/devices", "", ck); rr.Code != http.StatusOK {
		t.Fatalf("authenticated /api/devices: want 200, got %d", rr.Code)
	}

	if rr := do(s, http.MethodPost, "/api/auth/logout", "", ck); rr.Code != http.StatusOK {
		t.Fatalf("logout: %d", rr.Code)
	}
	if rr := do(s, http.MethodGet, "/api/devices", "", ck); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: want 401, got %d", rr.Code)
	}
}

func TestNoAuthConfigMeansOpen(t *testing.T) {
	s := New(testConfig(), nil, t.TempDir())
	if rr := do(s, http.MethodGet, "/api/devices", ""); rr.Code != http.StatusOK {
		t.Fatalf("without server.auth the API stays open, got %d", rr.Code)
	}
	if rr := do(s, http.MethodGet, "/api/auth/status", ""); !strings.Contains(rr.Body.String(), `"required":false`) {
		t.Errorf("auth status must report required=false: %s", rr.Body.String())
	}
}
