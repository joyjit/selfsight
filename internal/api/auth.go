package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
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
}

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
	if openPath(r.URL.Path) || !s.authRequired() || s.authenticated(r) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
	return false
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
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSONBody(w, r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"password\": \"...\"}"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(auth.Password)) != 1 {
		time.Sleep(500 * time.Millisecond) // damp brute force
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong password"})
		return
	}

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
