package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// The device config inside a backup is /sysconfig/config: one setting per line
// as "dotted:colon:key value". That flat, line-oriented shape is ideal for a
// readable history — each change is a line diff.

// Well-known members of a WAX backup tar (paths as the device tars them, with
// the leading slash stripped). The archive also carries optional database
// files; these three are the ones selfsight reasons about:
//
//   - ConfigPath is the whole device configuration.
//   - ShadowPath holds the login password hashes — this is why a restore
//     rolls the admin password back to whatever it was at backup time.
//   - DecryptedKeysPath must be present or the AP rejects the archive on
//     restore (its own validity check).
const (
	ConfigPath        = "sysconfig/config"
	ShadowPath        = "sysconfig/shadow"
	DecryptedKeysPath = "tmp/decryptedKeys"
)

// ErrMemberMissing reports that a decrypted backup tar has no such file.
var ErrMemberMissing = errors.New("backup: file not found in archive")

// Member returns the named file's content from a decrypted backup tar. Names
// are compared with any leading "/" or "./" stripped, matching how the device
// creates the archive.
func Member(plainTar []byte, name string) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(plainTar))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%w: %s", ErrMemberMissing, name)
		}
		if err != nil {
			return nil, fmt.Errorf("backup: reading archive: %w", err)
		}
		if strings.TrimPrefix(strings.TrimPrefix(h.Name, "./"), "/") == name {
			return io.ReadAll(tr)
		}
	}
}

// ExtractConfig pulls the plaintext /sysconfig/config out of a decrypted
// backup tar.
func ExtractConfig(plainTar []byte) ([]byte, error) {
	return Member(plainTar, ConfigPath)
}

// adminCredentialKey is the config field holding the web-admin login: the
// user name and the password. adminPasswd is a crypt(3)-style hash the AP
// computes itself, so selfsight cannot reverse it — but crucially, its stored
// value is STABLE across reboots (unlike sysconfig/shadow, which the device
// re-salts on every restart) and changes only when the password actually
// changes. That makes these two fields the reliable way to tell whether one
// backup carries the same login as another: compare the strings.
const (
	adminNameKey   = "system:basicSettings:adminName"
	adminPasswdKey = "system:basicSettings:adminPasswd"
)

// AdminCredential returns the "adminName + adminPasswd hash" pair from a
// decrypted backup's config as one comparable string. Two backups with an
// equal result carry the same web-admin login; an unequal result means the
// login differs (a restore of one onto the other would change it). An error
// means the config or those fields are missing — the caller decides how to
// fail.
func AdminCredential(plainTar []byte) (string, error) {
	cfg, err := ExtractConfig(plainTar)
	if err != nil {
		return "", err
	}
	var name, hash string
	haveName, haveHash := false, false
	for _, line := range strings.Split(string(cfg), "\n") {
		if key, val, ok := strings.Cut(line, " "); ok {
			switch key {
			case adminNameKey:
				name, haveName = val, true
			case adminPasswdKey:
				hash, haveHash = val, true
			}
		}
	}
	if !haveName || !haveHash {
		return "", errors.New("backup: config carries no admin credentials")
	}
	return name + "\x00" + hash, nil
}

// encBlob matches a config value that is an opaque encrypted-at-rest secret:
// a long lowercase-hex string. The WAX stores every credential in the config
// this way — WiFi pre-shared keys, RADIUS/WDS/802.1x shared secrets, radSec
// keys — so the config never held a readable password to begin with, only its
// wrapped form. The catch: the AP RE-WRAPS these (fresh encryption, same
// plaintext) on every reboot, so their stored value changes on every restart
// even when nothing really changed. 64+ hex digits is well clear of any
// incidental short fingerprint (an MD5 is 32, a SHA-1 40); the real blobs are
// 127 digits.
var encBlob = regexp.MustCompile(`^[0-9a-f]{64,}$`)

// volatileKeyTokens marks config keys whose values are device bookkeeping
// that changes on its own — timestamps of scheduled activity, not settings
// anyone chose. Like secretKeyTokens, a deliberately small fixed vocabulary:
// these fields caused every routine firmware check to look like a config
// change, spawning a backup and a history snapshot of pure noise.
var volatileKeyTokens = []string{"lastcheckeddate"}

func isVolatileKey(key string) bool {
	k := strings.ToLower(key)
	for _, tok := range volatileKeyTokens {
		if strings.Contains(k, tok) {
			return true
		}
	}
	return false
}

// StableConfig rewrites a config for the history log so it holds no secret and
// does not churn on reboots. Three rewrites, in this order:
//
//   - an opaque encrypted-at-rest value becomes a fixed placeholder (the AP
//     re-wraps these on every restart, so their stored form changes when
//     nothing really did);
//   - a volatile bookkeeping value (a self-updating timestamp) is blanked the
//     same way;
//   - anything else under a secret-bearing key — the admin password hash is
//     the one that matters — becomes a fingerprint of its value, exactly as
//     Redact does: you can see *that* it changed and when, without the value
//     being written down.
//
// The KEY always stays, so a field being added or removed still shows in
// history. The config kept in backups is untouched; this is only the readable
// history's view (and the change detector's, so bookkeeping no longer triggers
// backups).
//
// Trade-off: a genuine change to a re-wrapped secret will NOT show in history,
// because its stored form is indistinguishable from a reboot re-wrap. Nothing
// readable is lost — the config only ever held the wrapped form — and the
// audit value is in structure (SSIDs, VLANs, radios, hidden flags), which is
// fully preserved.
func StableConfig(config []byte) []byte {
	lines := strings.Split(string(config), "\n")
	for i, line := range lines {
		key, val, ok := strings.Cut(line, " ")
		switch {
		case !ok:
			// a line with no value; nothing to normalize
		case encBlob.MatchString(val):
			lines[i] = key + " «encrypted»"
		case isVolatileKey(key):
			lines[i] = key + " «volatile»"
		case val != "" && isSecretKey(key):
			lines[i] = key + " " + fingerprint(val)
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// secretKeyTokens are the case-insensitive substrings that mark a config key
// whose value is a secret (WiFi passphrases, admin/RADIUS credentials, private
// keys). Redaction is by key name, not value guessing, so a renamed-but-still-
// secret field is covered by adding a token here. This is a deliberately small,
// stable list — the config's secret-bearing fields are a fixed vocabulary.
var secretKeyTokens = []string{
	"presharedkey", "passphrase", "passwd", "password",
	"secret", "privatekey", "radiuskey", "wpakey", "pmk",
}

func isSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, tok := range secretKeyTokens {
		if strings.Contains(k, tok) {
			return true
		}
	}
	return false
}

// fingerprint is the stand-in a secret value is stored as: a short, stable
// hash of it. Stable means an unchanged secret produces no diff; short means
// the value cannot be recovered from it.
func fingerprint(val string) string {
	sum := sha256.Sum256([]byte(val))
	return "«redacted:" + hex.EncodeToString(sum[:4]) + "»"
}

// NOTE: history stores the config through StableConfig, which already replaces
// every secret-bearing value with a fingerprint (and every re-wrapped blob
// with a placeholder), so no readable secret reaches the history repository.
// Redact is the stricter, sorted form kept for a shareable export: it drops
// blank lines and orders the result so two snapshots diff cleanly.
//
// Redact rewrites a plaintext config so no secret value is retained: each
// secret line's value becomes "«redacted:<8 hex>»", a fingerprint of the value.
// The fingerprint is stable, so an unchanged secret produces no diff, but any
// change to it does — you learn *that* a WiFi password changed, and when,
// without the password ever being stored. Non-secret lines pass through
// unchanged. The result is deterministic (sorted) so snapshots diff cleanly.
func Redact(config []byte) []byte {
	lines := strings.Split(string(config), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if ok && val != "" && isSecretKey(key) {
			line = key + " " + fingerprint(val)
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return []byte(strings.Join(out, "\n") + "\n")
}

// RedactedConfig is the convenience pipeline: decrypted tar -> config ->
// redacted, sorted, safe-to-store snapshot.
func RedactedConfig(plainTar []byte) ([]byte, error) {
	cfg, err := ExtractConfig(plainTar)
	if err != nil {
		return nil, err
	}
	return Redact(cfg), nil
}
