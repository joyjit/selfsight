package wax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"selfsight/internal/device"
)

// logFile posts a /LogFile control message (backup/firmware live here) and
// returns the decoded response body.
func (c *Client) logFile(ctx context.Context, payload map[string]any) (map[string]json.RawMessage, error) {
	body := mustJSON(payload)
	var out map[string]json.RawMessage
	// /LogFile is warm-jar signed like /socketCommunication; reuse socket() by
	// posting to it would hit the wrong path, so do a direct signed POST.
	if err := c.postSigned(ctx, "/LogFile", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckFirmware asks the AP to query NETGEAR's cloud for a newer image, then
// reads the result. This is read-only on the device but reaches out to the
// vendor's servers, so it is a deliberate action, never automatic.
func (c *Client) CheckFirmware(ctx context.Context) (*Firmware, error) {
	// method 5: ask the AP to check the cloud now. A transient 500 from the
	// vendor is possible; the follow-up read is what matters.
	_, _ = c.logFile(ctx, map[string]any{"method": 5, "upgradeCheck": 0})
	return c.Firmware(ctx)
}

// UpgradeProgress is a single poll of an in-flight firmware upgrade.
type UpgradeProgress = device.UpgradeProgress

// Upgrade starts a firmware download+flash and drives it to completion, calling
// onProgress for each poll. THIS IS THE MOST DISRUPTIVE OPERATION IN THE DRIVER:
// it reboots the AP and drops every WiFi client, and an interrupted flash can
// require physical recovery. It must be run one AP at a time, only after a fresh
// backup, and never fleet-parallel. selfsight does not call this automatically.
//
// Protocol (from the AP's own JS, oracle-confirmed): method 7 starts it; method
// 6 with fwPercent 0 polls the download phase, then fwPercent 1 the flash phase;
// percent >100 are error sentinels; near the reboot boundary polls return no
// percent and must be ridden out. The caller confirms the new version via a
// fresh login + SystemInfo afterwards (a reboot kills the old session).
func (c *Client) Upgrade(ctx context.Context, onProgress func(UpgradeProgress)) error {
	if _, err := c.logFile(ctx, map[string]any{"method": 7, "fwUpgrade": 0}); err != nil {
		return fmt.Errorf("wax: upgrade start: %w", err)
	}
	if err := c.pollPhase(ctx, "download", 0, onProgress); err != nil {
		return err
	}
	return c.pollPhase(ctx, "flash", 1, onProgress)
}

func (c *Client) pollPhase(ctx context.Context, phase string, fwPercent int, onProgress func(UpgradeProgress)) error {
	iv := c.pollInterval
	if iv <= 0 {
		iv = 5 * time.Second
	}
	ticker := time.NewTicker(iv)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		resp, err := c.logFile(ctx, map[string]any{"method": 6, "fwPercent": fwPercent})
		if err != nil {
			// Near the reboot boundary the webserver dies mid-poll — ride it out.
			continue
		}
		pct := intField(resp["percent"])
		if pct > 100 {
			return fmt.Errorf("wax: upgrade %s error (sentinel %d)", phase, pct)
		}
		if onProgress != nil {
			onProgress(UpgradeProgress{Phase: phase, Percent: pct})
		}
		// Download done at percent 100; flash done when status flips to 100.
		if phase == "download" && pct >= 100 {
			return nil
		}
		if phase == "flash" && intField(resp["status"]) >= 100 {
			if onProgress != nil {
				onProgress(UpgradeProgress{Phase: phase, Percent: 100, Done: true})
			}
			return nil
		}
	}
}

func intField(raw json.RawMessage) int {
	if len(raw) == 0 {
		return -1
	}
	var s apiStatus
	if err := s.UnmarshalJSON(raw); err != nil {
		return -1
	}
	return int(s)
}

// CheckFirmware is the session-managed firmware check: the AP queries the
// vendor's cloud for a newer image. Read-only on the device, but it reaches
// out to NETGEAR's servers — a deliberate action, never run automatically.
func (m *Manager) CheckFirmware(ctx context.Context) (*Firmware, error) {
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return nil, err
		}
	}
	fw, err := m.client.CheckFirmware(ctx)
	if err != nil && m.recoverable(err) {
		if lerr := m.login(ctx); lerr != nil {
			return nil, lerr
		}
		fw, err = m.client.CheckFirmware(ctx)
	}
	if err != nil {
		return nil, err
	}
	_ = m.saveSession()
	return fw, nil
}

// UpgradeOutcome is the result of a completed firmware upgrade attempt.
type UpgradeOutcome = device.UpgradeOutcome

// Upgrade drives a firmware upgrade end to end: mandatory fresh config backup,
// download+flash (onProgress reports each poll), then — because the flash
// reboots the AP and kills every session — a fresh login to read the version
// actually running. Confirmed is true only when that read-back shows a new
// version; the upgrade machinery's own answers are never trusted.
//
// THE MOST DISRUPTIVE DRIVER OPERATION: reboots the AP, drops all clients, and
// an interrupted flash can require physical recovery. One AP at a time, never
// fleet-parallel — the caller enforces that.
func (m *Manager) Upgrade(ctx context.Context, backupDir string, onProgress func(UpgradeProgress)) (*UpgradeOutcome, error) {
	if m.pass == "" {
		return nil, errors.New("wax: upgrade needs the admin password (set the device's credentials)")
	}
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return nil, err
		}
	}
	si, err := m.client.SystemInfo(ctx)
	if err != nil && m.recoverable(err) {
		if lerr := m.login(ctx); lerr != nil {
			return nil, lerr
		}
		si, err = m.client.SystemInfo(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := &UpgradeOutcome{OldVersion: si.Firmware}

	// Hard rule: never a firmware flash without a fresh backup taken first.
	out.Backup, err = m.Backup(ctx, backupDir)
	if err != nil {
		return nil, fmt.Errorf("wax: upgrade aborted — pre-upgrade backup failed: %w", err)
	}

	if err := m.client.Upgrade(ctx, onProgress); err != nil {
		return nil, err
	}

	// The flash rebooted the device and killed our session. Log in fresh and
	// read what is actually running now.
	m.hasSession = false
	m.client.SetSession("", "")
	iv := m.client.pollInterval
	if iv <= 0 {
		iv = 5 * time.Second
	}
	for {
		if err := m.login(ctx); err == nil {
			if si, err := m.client.SystemInfo(ctx); err == nil {
				out.NewVersion = si.Firmware
				out.Confirmed = out.NewVersion != "" && out.NewVersion != out.OldVersion
				return out, nil
			}
		}
		select {
		case <-ctx.Done():
			return out, fmt.Errorf("wax: upgrade flashed but the device did not come back before the deadline — check it manually: %w", ctx.Err())
		case <-time.After(iv):
		}
	}
}
