package wax

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"selfsight/internal/device"
)

// maxRestoreArchive mirrors the AP's own upload validation: exactly one .tar,
// at most 2 MB.
const maxRestoreArchive = 2 << 20

// Restore uploads a config archive to the AP. THIS REBOOTS THE DEVICE and drops
// every connected WiFi client — a much larger blast radius than a config write.
//
// Protocol (oracle-confirmed): POST /restoreSettings as multipart/form-data,
// file field `file`, warm-jar signed plus the admin password in a `password`
// HEADER (not a body field). The response status is NOT a reliable success
// signal — a live test saw a "failure" code on a restore that in fact took —
// and, like radio-bouncing writes, the webserver may die mid-response as the
// reboot starts. Both are tolerated here; the caller confirms success via the
// session-reset check (Manager.Restore), never from this call's outcome.
func (c *Client) Restore(ctx context.Context, adminPassword, filename string, archive []byte) error {
	if !strings.HasSuffix(strings.ToLower(filename), ".tar") {
		return fmt.Errorf("wax: restore: %q is not a .tar archive", filename)
	}
	if len(archive) == 0 {
		return errors.New("wax: restore: archive is empty")
	}
	if len(archive) > maxRestoreArchive {
		return fmt.Errorf("wax: restore: archive is %d bytes, above the AP's 2MB limit", len(archive))
	}
	if c.token == "" {
		return ErrAuthExpired
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(archive); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	base, err := c.base(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/restoreSettings", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c.sign(req)
	req.Header.Set("password", adminPassword)

	resp, err := c.http.Do(req)
	if err != nil {
		// The reboot can kill the connection before a response arrives; the
		// session-reset check decides whether the restore took.
		return nil //nolint:nilerr // deliberate: write responses are never trusted
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	return nil
}

// RestoreResult is the outcome of a guarded restore.
type RestoreResult = device.RestoreResult

// Restore uploads an ENCRYPTED archive (the caller encrypts a stored decrypted
// backup with the current admin password first — the AP decrypts the upload
// with the password header) and confirms the outcome. A restore only takes
// effect through a reboot, and a reboot kills every session on the device — so
// the proof that it happened is that the pre-restore session STOPS
// authenticating. Plain reachability proves nothing (a rejected upload leaves
// the AP up throughout), and the AP's response status is untrustworthy, so
// this session-reset check is the only signal used.
//
// wait bounds how long to poll for the device to settle (reboot observed at
// ~25s live; give it comfortably more). Like every fleet-affecting operation,
// callers must run restores strictly one device at a time.
func (m *Manager) Restore(ctx context.Context, filename string, archive []byte, wait time.Duration) (*RestoreResult, error) {
	if m.pass == "" {
		return nil, errors.New("wax: restore needs the admin password (set the device's credentials)")
	}
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return nil, err
		}
	}

	name := filepath.Base(filename)
	if err := m.client.Restore(ctx, m.pass, name, archive); err != nil {
		return nil, err
	}

	rebooted, err := m.waitSessionReset(ctx, wait)
	if err != nil {
		return nil, err
	}
	if rebooted {
		// The old session died with the reboot; forget it so the next call
		// logs in fresh instead of reading back a confusing 100.
		m.hasSession = false
		m.client.SetSession("", "")
		_ = os.Remove(m.sessPath)
	}
	return &RestoreResult{File: name, Rebooted: rebooted}, nil
}

// waitSessionReset polls the device with the PRE-restore session and reports
// whether that session was killed (i.e. the device rebooted):
//
//   - the old session stops authenticating (401/100) → rebooted, true
//   - the old session still works when wait expires → no reboot, false
//     (the restore did not take)
//   - the device never answers before wait expires → error: mid-reboot when
//     time ran out, or genuinely down — the caller must check on it
func (m *Manager) waitSessionReset(ctx context.Context, wait time.Duration) (bool, error) {
	iv := m.client.pollInterval
	if iv <= 0 {
		iv = 5 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		_, err := m.client.SystemInfo(ctx)
		switch {
		case err == nil:
			if time.Now().After(deadline) {
				return false, nil // old session survived the whole window: no reboot
			}
		case errors.Is(err, ErrAuthExpired) || errors.Is(err, ErrManaged):
			return true, nil // old session is dead: the device rebooted
		default:
			// Transport error — the device is down mid-reboot. Keep polling.
			if time.Now().After(deadline) {
				return false, fmt.Errorf("wax: restore: device did not answer within %s — verify it manually: %w", wait, err)
			}
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(iv):
		}
	}
}
