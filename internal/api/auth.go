package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Session cookie for the selfsight UI itself (not the AP sessions). Tokens are
// random, held in memory only — a server restart logs everyone out, which is
// the right failure mode for a security boundary.
const (
	sessionCookie = "selfsight_session"
	sessionTTL    = 24 * time.Hour
)

type authState struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token -> expiry
	attempts map[string]*loginAttempts
}

// loginAttempts counts one source address's recent failed logins.
type loginAttempts struct {
	failures int
	first    time.Time // when the current window started
}

// A source address gets this many wrong passwords per window before it is
// locked out. Generous for a fat-fingered human, hopeless for a guesser: five
// tries every five minutes is under 1500 a day against a password that only
// has to be moderately good.
const (
	loginMaxFailures = 5
	loginWindow      = 5 * time.Minute
)

// authRequired reports whether the current config demands a login.
func (s *Server) authRequired() bool { return s.config().Server.Auth != nil }

// authenticated reports whether the request carries a live session cookie,
// sliding the expiry forward on use.
func (s *Server) authenticated(r *http.Request) bool {
	ck, err := r.Cookie(sessionCookie)
	if err != nil || ck.Value == "" {
		return false
	}
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	exp, ok := s.auth.sessions[ck.Value]
	if !ok || time.Now().After(exp) {
		delete(s.auth.sessions, ck.Value)
		return false
	}
	s.auth.sessions[ck.Value] = time.Now().Add(sessionTTL)
	return true
}

// clearSessions logs everyone out. Called when the login password changes (or
// auth is switched on or off): a session minted under the old password must
// not survive the change, or "I rotated the password" would not actually evict
// anybody already inside.
func (s *Server) clearSessions() {
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	s.auth.sessions = nil
}

// gatePath is the request path in the one form the gates compare against:
// collapsed so that no "." or ".." segment survives. The router does its own
// cleaning, so without this a path like "/api/auth/../devices" would look open
// here and reach the devices handler anyway.
func gatePath(r *http.Request) string {
	return path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
}

// openPath lists what works without a login: the SPA itself (it renders the
// login form), health, and the auth endpoints.
func openPath(p string) bool {
	if !strings.HasPrefix(p, "/api/") {
		return true // static UI
	}
	return p == "/api/healthz" || strings.HasPrefix(p, "/api/auth/")
}

// requireAuth is the gate in front of the API. It re-reads the config each
// request, so enabling/disabling auth via config reload takes effect
// immediately.
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if openPath(gatePath(r)) || !s.authRequired() || s.authenticated(r) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
	return false
}

// csrfHeader is the value the dashboard sends in X-Requested-With on every
// request. A browser will not attach a custom header to a form post, an image
// load or any other request another site can make on the user's behalf, so its
// presence is proof the request came from selfsight's own code.
const csrfHeader = "selfsight"

// requireSameSite refuses a state-changing request that another site could
// have talked the user's browser into sending, with the session cookie riding
// along. Two checks, neither of which a hostile page can satisfy:
//
//   - if the browser told us where the request came from (Origin), it has to
//     be this server;
//   - the request must be JSON or carry the custom header above — a plain
//     cross-site form can be neither.
//
// The auth endpoints and the health check are exempt: forcing a stranger's
// browser to log in or out of this server, or to ask if it is alive, gains an
// attacker nothing.
func (s *Server) requireSameSite(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return true // safe method: nothing changes
	}
	switch gatePath(r) {
	case "/api/auth/login", "/api/auth/logout", "/api/healthz":
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "this request came from " + origin + ", not from " + r.Host + " — refused",
			})
			return false
		}
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), csrfHeader) {
		return true
	}
	if ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); strings.HasPrefix(ct, "application/json") {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error": `refused: a request that changes something must be sent as application/json or carry the header "X-Requested-With: selfsight"`,
	})
	return false
}

// contentSecurityPolicy locks the page down to what selfsight itself serves:
// no third-party scripts, no framing, no plugin content. Styles need
// 'unsafe-inline' because the UI toolkit injects component styles as inline
// <style> elements while the page runs; scripts do not, so they stay strict.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// setSecurityHeaders applies the browser-side defenses to every response,
// including the dashboard's own files: content-type guessing off, framing off
// (so the UI cannot be hidden under a decoy page), no referrer leaking a
// device name to anywhere the user clicks through to.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"required":      s.authRequired(),
		"authenticated": !s.authRequired() || s.authenticated(r),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	auth := s.config().Server.Auth
	if auth == nil {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) // nothing to log into
		return
	}
	ip := sourceAddr(r)
	if wait, blocked := s.loginBlocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("too many failed logins from this address — try again in %s", wait.Round(time.Second)),
		})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"password\": \"...\"}"})
		return
	}
	// Constant-time so the comparison itself reveals nothing about how much of
	// the password was right.
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(auth.Password)) != 1 {
		s.noteLoginFailure(ip)
		time.Sleep(250 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong password"})
		return
	}
	s.clearLoginFailures(ip)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	token := hex.EncodeToString(raw)
	now := time.Now()
	s.auth.mu.Lock()
	if s.auth.sessions == nil {
		s.auth.sessions = map[string]time.Time{}
	}
	for t, exp := range s.auth.sessions { // lazy cleanup
		if now.After(exp) {
			delete(s.auth.sessions, t)
		}
	}
	s.auth.sessions[token] = now.Add(sessionTTL)
	s.auth.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: viaHTTPS(r),
		MaxAge: int(sessionTTL / time.Second),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// sourceAddr is the address a request came from, without the port — the key
// the login limiter counts failures against.
func sourceAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// loginBlocked reports whether an address has spent its budget of wrong
// passwords, and how long it stays locked out.
//
// A per-address limit replaces the fixed delay this used to have on every
// attempt: a delay slows one guesser but not a hundred running in parallel,
// and it makes an honest typo feel like a broken server.
func (s *Server) loginBlocked(ip string) (time.Duration, bool) {
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	a := s.auth.attempts[ip]
	if a == nil || a.failures < loginMaxFailures {
		return 0, false
	}
	if left := loginWindow - time.Since(a.first); left > 0 {
		return left, true
	}
	delete(s.auth.attempts, ip)
	return 0, false
}

// noteLoginFailure records a wrong password from ip, starting a fresh window
// if the last one has expired. Windows that have run out are swept here too,
// so the table cannot grow without bound.
func (s *Server) noteLoginFailure(ip string) {
	now := time.Now()
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	if s.auth.attempts == nil {
		s.auth.attempts = map[string]*loginAttempts{}
	}
	for k, v := range s.auth.attempts {
		if now.Sub(v.first) > loginWindow {
			delete(s.auth.attempts, k)
		}
	}
	a := s.auth.attempts[ip]
	if a == nil {
		a = &loginAttempts{first: now}
		s.auth.attempts[ip] = a
	}
	a.failures++
}

// clearLoginFailures forgets an address's failures after a correct password.
func (s *Server) clearLoginFailures(ip string) {
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	delete(s.auth.attempts, ip)
}

// viaHTTPS reports whether the request reached us over TLS — directly, or at a
// reverse proxy / tunnel that terminated it (the standard X-Forwarded-Proto
// signal). Used to mark the session cookie Secure so a browser never sends it
// over plaintext once the deployment has HTTPS in front.
func viaHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		s.auth.mu.Lock()
		delete(s.auth.sessions, ck.Value)
		s.auth.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: viaHTTPS(r), MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
