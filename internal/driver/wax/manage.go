package wax

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"selfsight/internal/device"
)

// Status is a full read of an AP's live state (vendor-neutral shape).
type Status = device.Status

// Status reads the AP's full state. SystemInfo is required (its error is
// returned); the remaining reads are best-effort so one flaky sub-read doesn't
// sink the whole status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	si, err := c.SystemInfo(ctx)
	if err != nil {
		return nil, err
	}
	st := &Status{System: si}
	if v, e := c.SSIDs(ctx); e == nil {
		st.SSIDs = v
	}
	if v, e := c.Clients(ctx); e == nil {
		st.Clients = v
	}
	if v, e := c.ClientList(ctx); e == nil {
		st.ClientList = v
	}
	if v, e := c.RadioSettings(ctx); e == nil {
		st.RadioSettings = v
	}
	if v, e := c.Firmware(ctx); e == nil {
		st.Firmware = v
	}
	return st, nil
}

// Manager owns one AP's warm session end to end: it reuses a persisted cookie,
// logs in only when the session is missing or dead, and re-saves on success. It
// is the single place session lifecycle lives, shared by the probe CLI and the
// server. A Manager is not safe for concurrent use — serialize calls per device.
type Manager struct {
	host, sessPath, user, pass string
	client                     *Client
	hasSession                 bool
	// Read-back patience after a write: wireless writes bounce the radio and
	// the AP's web server can stay silent for tens of seconds, so transport
	// failures during verify are retried until this budget runs out.
	// Overridable for tests; zero values fall back to the defaults.
	verifyPatience time.Duration
	verifyGap      time.Duration
}

const (
	defaultVerifyPatience = 90 * time.Second
	defaultVerifyGap      = 5 * time.Second
)

// NewManager builds a session-managing client for host, loading any saved
// session from sessPath. user/pass may be empty (then it can only reuse an
// existing/injected session, never log in).
func NewManager(host, sessPath, user, pass string, opts ...Option) *Manager {
	m := &Manager{host: host, sessPath: sessPath, user: user, pass: pass, client: New(host, opts...)}
	// A saved session recorded for a different host is discarded, not reused:
	// the device entry was re-pointed since it was saved, and the next call
	// should log in fresh against the current host. (No recorded host means a
	// legacy file — its path already ties it to this host.)
	if s, err := LoadSession(sessPath); err == nil && s.Valid() && (s.Host == "" || s.Host == host) {
		m.client.SetSession(s.Token, s.LHTTPDSID)
		m.hasSession = true
	}
	return m
}

// saveSession persists the client's warm session stamped with the host it
// belongs to, so a later run can refuse to replay it elsewhere.
func (m *Manager) saveSession() error {
	s := m.client.Session()
	s.Host = m.host
	return s.Save(m.sessPath)
}

// SetSession injects a session (e.g. one supplied on the command line) and
// persists it, so later runs reuse it.
func (m *Manager) SetSession(token, lhttpdsid string) {
	m.client.SetSession(token, lhttpdsid)
	m.hasSession = true
	_ = m.saveSession()
}

// Status reads full status, reusing the saved session and (re)logging-in when it
// is missing or has died (401, or 100 from a displaced session). A successful
// session is persisted for the next call.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return nil, err
		}
	}
	st, err := m.client.Status(ctx)
	if err != nil && m.recoverable(err) {
		if lerr := m.login(ctx); lerr != nil {
			return nil, lerr
		}
		st, err = m.client.Status(ctx)
	}
	if err != nil {
		return nil, err
	}
	_ = m.saveSession()
	return st, nil
}

// recoverable reports whether err is a dead session we can fix by logging in
// again (we have credentials, and the AP said auth-expired or session-locked).
func (m *Manager) recoverable(err error) bool {
	return m.user != "" && (errors.Is(err, ErrAuthExpired) || errors.Is(err, ErrManaged))
}

// Backup downloads the device's config archive (session-managed) and writes it
// into dir, returning the file path. Read-only on the device. Requires
// credentials (the AP re-confirms the admin password to release a backup).
func (m *Manager) Backup(ctx context.Context, dir string) (string, error) {
	if m.pass == "" {
		return "", errors.New("wax: backup needs the admin password (set the device's credentials)")
	}
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return "", err
		}
	}
	b, err := m.client.Backup(ctx, m.pass)
	if err != nil && m.recoverable(err) {
		if lerr := m.login(ctx); lerr != nil {
			return "", lerr
		}
		b, err = m.client.Backup(ctx, m.pass)
	}
	if err != nil {
		return "", err
	}
	_ = m.saveSession()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// The filename comes from the device — take only its base name so a hostile
	// Content-Disposition can't escape dir.
	path := filepath.Join(dir, filepath.Base(b.Filename))
	if err := os.WriteFile(path, b.Data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Change is one guarded configuration change: how to write it and how to
// confirm it by reading the device back.
type Change struct {
	Describe string
	Write    func(context.Context, *Client) error
	// Verify reads the device and reports whether the change took, with a short
	// human-readable observed value.
	Verify func(context.Context, *Client) (ok bool, observed string, err error)
}

// ApplyResult is the outcome of a guarded apply.
type ApplyResult = device.ApplyResult

// Apply runs the guarded write pipeline: fresh backup → write → re-read →
// verify. A write is reported applied ONLY when the read-back confirms it
// (DESIGN.md, "The apply path"); the write response itself is never trusted, and
// the change is aborted if the mandatory pre-write backup fails.
//
// Callers must serialize applies across the fleet (writes bounce the radio) —
// the server holds a per-device lock and never applies to devices in parallel.
func (m *Manager) Apply(ctx context.Context, backupDir string, ch Change) (*ApplyResult, error) {
	if m.pass == "" {
		return nil, errors.New("wax: apply needs the admin password (set the device's credentials)")
	}
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return nil, err
		}
	}

	// Hard rule: never write without a fresh backup taken immediately before.
	backup, err := m.Backup(ctx, backupDir)
	if err != nil {
		return nil, fmt.Errorf("wax: apply aborted — pre-write backup failed: %w", err)
	}

	if err := ch.Write(ctx, m.client); err != nil {
		if m.recoverable(err) { // session died mid-apply — re-login and write once more
			if lerr := m.login(ctx); lerr != nil {
				return nil, lerr
			}
			if werr := ch.Write(ctx, m.client); werr != nil {
				return nil, werr
			}
		} else {
			return nil, err
		}
	}

	// Wireless writes bounce the radio, and the AP's web server often goes
	// quiet for tens of seconds while the Wi-Fi stack restarts. A verify that
	// fails on transport (or on a session the bounce displaced) is retried
	// until the patience budget runs out; a definitive answer from the device
	// — confirmed or not — is never retried.
	patience, gap := m.verifyPatience, m.verifyGap
	if patience == 0 {
		patience = defaultVerifyPatience
	}
	if gap == 0 {
		gap = defaultVerifyGap
	}
	deadline := time.Now().Add(patience)
	var ok bool
	var observed string
	for {
		ok, observed, err = ch.Verify(ctx, m.client)
		if err == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil, fmt.Errorf("wax: apply wrote but could not read back to verify (kept trying for %s while the AP restarted its Wi-Fi): %w", patience, err)
		}
		if m.recoverable(err) {
			_ = m.login(ctx) // best effort; the next verify attempt decides
			continue
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wax: apply wrote but could not read back to verify: %w", ctx.Err())
		case <-time.After(gap):
		}
	}
	_ = m.saveSession()
	return &ApplyResult{Change: ch.Describe, Backup: backup, Applied: ok, Observed: observed}, nil
}

// APNameChange is a guarded change that sets the device name — the simplest
// write (a basicSettings leaf, no radio bounce), used as the reference apply.
func APNameChange(name string) Change {
	return Change{
		Describe: "set apName to " + name,
		Write:    func(ctx context.Context, c *Client) error { return c.SetAPName(ctx, name) },
		Verify: func(ctx context.Context, c *Client) (bool, string, error) {
			si, err := c.SystemInfo(ctx)
			if err != nil {
				return false, "", err
			}
			return si.Name == name, "apName=" + si.Name, nil
		},
	}
}

func (m *Manager) login(ctx context.Context) error {
	if m.user == "" {
		return errors.New("wax: no session and no credentials to log in with")
	}
	_ = os.Remove(m.sessPath) // drop any dead cookie
	if err := m.client.Login(ctx, m.user, m.pass); err != nil {
		return err
	}
	m.hasSession = true
	return m.saveSession()
}
