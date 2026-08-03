package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"selfsight/internal/core"
	"selfsight/internal/device"
)

// Stored-backup pipeline. selfsight stores backups DECRYPTED — the decoded
// config set is the source of truth, and a restore re-encrypts it with the
// device's current admin password on the way out. That kills the old trap
// where an archive could only be decrypted with whatever the admin password
// happened to be when it was taken.
//
// The conversion is gated by proof: the plaintext is re-encrypted with the
// archive's own salt/IV and must reproduce the AP's bytes exactly
// (backup.VerifyRoundTrip) before the encrypted form is let go. An archive
// that fails that (wrong/old password) is kept encrypted as-is.

// finishBackup takes a just-downloaded archive and puts it in stored form:
// timestamp-prefixed name (so same-day backups never overwrite), decrypted
// content, and a history commit of the config inside. Returns the final path.
// A conversion or history failure is returned for logging but the file — in
// whatever form it reached disk — is always kept.
func (s *Server) finishBackup(dev *core.Device, rawPath string, when time.Time) (string, error) {
	path := rawPath
	stamped := filepath.Join(filepath.Dir(rawPath),
		when.UTC().Format("20060102T150405Z")+"-"+filepath.Base(rawPath))
	if err := os.Rename(rawPath, stamped); err == nil {
		path = stamped
	}
	return path, s.storeDecrypted(dev, path, when)
}

// finishApplyBackup runs finishBackup on the pre-write backup an Apply just
// took and points the result at the file's final name. Best-effort: a
// conversion problem is logged and never fails the apply it guarded.
func (s *Server) finishApplyBackup(dev *core.Device, res *device.ApplyResult) {
	if res == nil || res.Backup == "" {
		return
	}
	path, err := s.finishBackup(dev, res.Backup, time.Now())
	res.Backup = path
	if err != nil {
		log.Printf("backup post-process %s: %v", dev.Name, err)
	}
}

// snapshotAfterApply captures the device's NEW config right after a change
// actually took, so there is an immediate restore point and the config history
// reflects the change at once — instead of waiting up to a whole watcher
// interval for the periodic check to notice. The pre-write backup only holds
// the OLD state, so without this the most recent change sits un-snapshotted.
//
// Fired once per request (not per result). Synchronous and best-effort: the
// caller already holds dm.mu (so this uses backupIfChangedLocked to avoid a
// deadlock), and an apply already waits out the write and read-back, so one
// more backup is a small addition and keeps the snapshot deterministic. It
// dedups — an unchanged config stores nothing — and its own failures are
// logged, never surfaced as an apply error.
func (s *Server) snapshotAfterApply(ctx context.Context, dev *core.Device, dm *deviceManager, results []*device.ApplyResult) {
	for _, r := range results {
		if r != nil && r.Applied {
			s.backupIfChangedLocked(ctx, dev, dm)
			return
		}
	}
}

// storeDecrypted converts one stored archive to plaintext in place (round-trip
// proof first, atomic replace, mtime preserved so retention order is
// unaffected) and records its config in history. An already-plain archive is
// just recorded.
func (s *Server) storeDecrypted(dev *core.Device, path string, when time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain := data
	if s.codec.IsEncrypted(data) {
		plain, err = s.codec.Decrypt(data, dev.Password)
		if err != nil {
			return fmt.Errorf("keeping %s encrypted: %w", filepath.Base(path), err)
		}
		info, statErr := os.Stat(path)
		tmp := path + ".decrypting"
		if err := os.WriteFile(tmp, plain, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
		if statErr == nil {
			_ = os.Chtimes(path, info.ModTime(), info.ModTime())
		}
	}
	return s.recordConfigHistory(dev, plain, when)
}

// recordConfigHistory commits the config out of a decrypted backup to the
// history store. The config is stored in full — including secret values — by
// explicit decision: the history repo is local-only and must never be pushed
// (see backup.HistoryStore). Best-effort: any failure is returned for logging
// but never affects the backup itself.
func (s *Server) recordConfigHistory(dev *core.Device, plainTar []byte, when time.Time) error {
	if s.history == nil {
		return nil
	}
	cfg, err := s.codec.ExtractConfig(plainTar)
	if err != nil {
		return err
	}
	// Opaque encrypted-at-rest secrets re-wrap on every reboot; normalize them
	// so history diffs reflect real changes, not restarts.
	cfg = s.codec.StableView(cfg)
	_, err = s.history.Record(dev.Name, cfg, when, "backup "+when.UTC().Format(time.RFC3339))
	return err
}

func (s *Server) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if s.history == nil {
		writeJSON(w, http.StatusOK, map[string]any{"device": dev.Name, "history": []any{}})
		return
	}
	snaps, err := s.history.History(dev.Name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": dev.Name, "history": snaps})
}

// handleConfigHistoryDiff returns the change between two snapshots (query params
// from & to, as commit hashes from the history list). An omitted from diffs
// against nothing (the whole snapshot as additions).
func (s *Server) handleConfigHistoryDiff(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	if s.history == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config history is not enabled"})
		return
	}
	to := r.URL.Query().Get("to")
	if to == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query param 'to' (a commit hash) is required"})
		return
	}
	diff, summary, err := s.history.Diff(dev.Name, r.URL.Query().Get("from"), to)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": dev.Name, "diff": diff, "summary": summary})
}

// ConvertAndBackfill walks every backup already on disk, converts encrypted
// archives to the decrypted stored form (oldest first, so history commits
// match real chronology), and seeds the history store from them. Runs at
// startup. Best-effort per archive: one that cannot be decrypted (a password
// changed since it was taken) stays encrypted and is skipped, with a log line
// so the gap is visible.
func (s *Server) ConvertAndBackfill() {
	cfg := s.config()
	for i := range cfg.Devices {
		dev := &cfg.Devices[i]
		dir := s.deviceDataDir(dev.Name)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		type arch struct {
			path string
			mod  time.Time
		}
		var archives []arch
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			archives = append(archives, arch{path: filepath.Join(dir, e.Name()), mod: info.ModTime()})
		}
		sort.Slice(archives, func(a, b int) bool { return archives[a].mod.Before(archives[b].mod) })
		for _, a := range archives {
			if err := s.storeDecrypted(dev, a.path, a.mod); err != nil {
				log.Printf("backup convert %s: %v", dev.Name, err)
			}
		}
	}
}
