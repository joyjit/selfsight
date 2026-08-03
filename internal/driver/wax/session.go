package wax

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Session is a warm AP session — the two secrets that let the driver replay a
// browser-established login: the security token and the lhttpdsid cookie.
//
// Sessions are persisted and reused: a browser login (or an injected token) is
// expensive and consumes one of the AP's limited login slots, and a cookie
// stays valid on the device far longer than any local bookkeeping. The driver
// reuses a saved session until the AP rejects it (ErrAuthExpired), and only then
// mints a fresh one.
type Session struct {
	Token     string `json:"token"`
	LHTTPDSID string `json:"lhttpdsid"`
	// Host is who this session was minted against. A session is only ever
	// replayed to that same host: a device entry re-pointed at a different
	// address may be different hardware, and replaying a foreign cookie there
	// just burns time on requests the AP will reject.
	Host    string    `json:"host,omitempty"`
	SavedAt time.Time `json:"savedAt"`
}

// Valid reports whether the session has both secrets.
func (s Session) Valid() bool { return s.Token != "" && s.LHTTPDSID != "" }

// DefaultSessionPath is where a session for host is cached, under the user cache
// dir (e.g. ~/.cache/selfsight/wax-192.0.2.20.json).
func DefaultSessionPath(host string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "selfsight", "wax-"+host+".json"), nil
}

// LoadSession reads a persisted session. A missing file returns (zero, nil) so
// callers can treat "no session yet" as an ordinary first run.
func LoadSession(path string) (Session, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Session{}, nil
		}
		return Session{}, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return Session{}, fmt.Errorf("wax: parse session %s: %w", path, err)
	}
	return s, nil
}

// Save writes the session to path (0600 — it holds credentials-equivalent
// secrets), creating the parent directory as needed.
func (s Session) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	s.SavedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
