package wax

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Certificate pinning, trust-on-first-use. AP certificates are self-signed so
// classic chain verification is impossible; instead the first successful
// connection records the SHA-256 of the device's leaf certificate, and every
// later connection must present the same one. A mismatch fails the connection
// — either the device legitimately re-keyed (factory reset, some firmware
// updates) or something is impersonating it; the human decides, by deleting
// the pin file to re-trust.

// WithPinPath enables trust-on-first-use certificate pinning, storing the pin
// in the file at path. Ignored if the HTTP client was overridden
// (WithHTTPClient — tests bring their own trust).
func WithPinPath(path string) Option { return func(c *Client) { c.pinPath = path } }

// DefaultPinPath is where host's certificate pin lives, next to its session
// (e.g. ~/.cache/selfsight/pin-3f7a1c9d8e2b4a06.txt).
func DefaultPinPath(host string) (string, error) {
	base, err := DefaultCacheDir()
	if err != nil {
		return "", err
	}
	return PinPathIn(base, host), nil
}

// PinPathIn is DefaultPinPath under an explicit cache directory, for a
// deployment that has no user cache dir of its own.
func PinPathIn(base, host string) string {
	return filepath.Join(base, "pin-"+hostKey(host)+".txt")
}

// DefaultCacheDir is where the driver keeps its per-host caches (sessions and
// certificate pins) when the caller has no directory of its own.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "selfsight"), nil
}

// hostKey turns a device address into a file-name component: the first 16 hex
// digits of its SHA-256. Hashing rather than embedding the address means no
// host string — however odd, and whatever validation upstream may have missed
// — can steer a cache file out of its directory, and it keeps the addresses of
// a fleet off the filesystem. It is stable, so a host keeps its own cache
// across restarts.
func hostKey(host string) string {
	sum := sha256.Sum256([]byte(host))
	return hex.EncodeToString(sum[:8])
}

var pinMu sync.Mutex // pin files are per-host but cheap; one lock is fine

// verifyPin is the tls.Config.VerifyPeerCertificate hook.
func (c *Client) verifyPin(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("wax: %s presented no certificate", c.host)
	}
	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])

	pinMu.Lock()
	defer pinMu.Unlock()
	b, err := os.ReadFile(c.pinPath)
	if os.IsNotExist(err) {
		// First contact: trust and record.
		if err := os.MkdirAll(filepath.Dir(c.pinPath), 0o700); err != nil {
			return err
		}
		return os.WriteFile(c.pinPath, []byte(got+"\n"), 0o600)
	}
	if err != nil {
		return err
	}
	want := strings.TrimSpace(string(b))
	if want != got {
		return fmt.Errorf("wax: %s certificate changed (pinned %.12s…, got %.12s…) — if the device legitimately re-keyed, delete %s to re-trust it",
			c.host, want, got, c.pinPath)
	}
	return nil
}
