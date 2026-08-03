package api

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"selfsight/internal/core"
)

// keepPerDevice caps stored archives per device. Change-triggered backups are
// sparse (only real changes are kept), so this is deliberately generous; the
// config history (git) keeps the full record regardless.
const keepPerDevice = 30

// RunBackupWatcher checks each device for a config change and stores a backup
// only when it finds one, until ctx is canceled — it never backs up an
// unchanged config. Changes selfsight makes itself are already captured by the
// fresh backup the hard rule takes before every write; this is what catches a
// change made directly on the AP. The fleet is visited one device at a time.
//
// It runs an initial check shortly after startup (so a change made while
// selfsight was down, or right before a restart, is caught promptly instead of
// waiting a whole interval), then repeats on the routine interval. Both timings
// come from server.backupCheck (with defaults); the interval is re-read each
// cycle so a config reload can retune it without a restart.
func (s *Server) RunBackupWatcher(ctx context.Context) {
	// Validated at load, so the error can't fire here; the defaults it returns
	// on error just mean the watcher keeps working rather than silently stopping.
	delay, _, _ := s.config().Server.BackupCheck.Durations()
	if !sleepOrDone(ctx, delay) {
		return
	}
	s.backupRound(ctx)

	for {
		_, interval, _ := s.config().Server.BackupCheck.Durations()
		if !sleepOrDone(ctx, interval) {
			return
		}
		s.backupRound(ctx)
	}
}

// sleepOrDone waits for d or until ctx is canceled; it returns false if ctx was
// canceled (the caller should stop).
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// backupRound checks each configured device once, in order, storing a backup
// for any whose config changed since its last one. One device's failure is
// logged and does not stop the round.
func (s *Server) backupRound(ctx context.Context) {
	// The watcher's cadence doubles as the check for the one change nothing
	// else notices: the config file edited on disk behind the dashboard's back.
	s.checkConfigFile()
	cfg := s.config()
	for i := range cfg.Devices {
		if ctx.Err() != nil {
			return
		}
		s.backupIfChanged(ctx, &cfg.Devices[i])
	}
}

// backupIfChanged pulls dev's current config and keeps it as a new backup only
// when it differs from the most recent stored backup — so an unchanged config
// never produces a redundant archive or history commit. If it cannot tell
// (e.g. the previous archive won't decrypt), it keeps the pull rather than
// risk dropping a real change.
func (s *Server) backupIfChanged(ctx context.Context, dev *core.Device) {
	dm := s.managerFor(dev)
	dm.mu.Lock()
	defer dm.mu.Unlock()
	s.backupIfChangedLocked(ctx, dev, dm)
}

// backupIfChangedLocked is backupIfChanged's body, assuming the caller already
// holds dm.mu. The apply handlers hold that lock for the whole request, so they
// call this directly to snapshot the NEW config right after a change without
// re-locking (which would deadlock).
func (s *Server) backupIfChangedLocked(ctx context.Context, dev *core.Device, dm *deviceManager) {
	dir := s.deviceDataDir(dev.Name)

	raw, err := dm.mgr.Backup(ctx, dir)
	if err != nil {
		log.Printf("backup check %s: %v", dev.Name, err)
		return
	}

	changed, err := s.backupDiffersFromLatest(dir, raw, dev.Password)
	if err != nil {
		log.Printf("backup check %s: comparing to last backup: %v (keeping)", dev.Name, err)
		changed = true
	}
	if !changed {
		_ = os.Remove(raw) // config unchanged — nothing to record
		return
	}

	path, err := s.finishBackup(dev, raw, time.Now())
	if err != nil {
		log.Printf("backup check %s: %v", dev.Name, err)
	}
	log.Printf("backup check %s: config changed, stored %s", dev.Name, filepath.Base(path))
	if err := pruneBackups(dir, keepPerDevice); err != nil {
		log.Printf("backup check %s: prune: %v", dev.Name, err)
	}
}

// backupDiffersFromLatest reports whether the freshly pulled archive at rawPath
// has a different config from the newest already-stored backup in dir. The
// comparison is on the StableConfig-normalized config, so the AP re-wrapping
// its encrypted-at-rest secrets on a reboot does not read as a change. With no
// prior backup it is a change (there is nothing to match).
func (s *Server) backupDiffersFromLatest(dir, rawPath, password string) (bool, error) {
	prev := latestStoredBackup(dir, rawPath)
	if prev == "" {
		return true, nil
	}
	fresh, err := s.stableConfigOfArchiveFile(rawPath, password)
	if err != nil {
		return false, err
	}
	last, err := s.stableConfigOfArchiveFile(prev, password)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(fresh, last), nil
}

// stableConfigOfArchiveFile reads a backup archive (encrypted or already
// decrypted) and returns its config normalized for change detection.
func (s *Server) stableConfigOfArchiveFile(path, password string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plain := data
	if s.codec.IsEncrypted(data) {
		if plain, err = s.codec.Decrypt(data, password); err != nil {
			return nil, err
		}
	}
	cfg, err := s.codec.ExtractConfig(plain)
	if err != nil {
		return nil, err
	}
	return s.codec.StableView(cfg), nil
}

// latestStoredBackup returns the path of the newest file in dir by modification
// time, skipping exclude (the just-pulled raw archive). Empty if none.
func latestStoredBackup(dir, exclude string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var newest string
	var newestMod time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if p == exclude {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest, newestMod = p, info.ModTime()
		}
	}
	return newest
}

// pruneBackups deletes all but the newest keep archives in dir (by modification
// time). keep <= 0 keeps everything.
func pruneBackups(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type file struct {
		name string
		mod  time.Time
	}
	var files []file
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, file{e.Name(), info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	for _, f := range files[min(keep, len(files)):] {
		if err := os.Remove(filepath.Join(dir, f.name)); err != nil {
			return err
		}
	}
	return nil
}

// handleListBackups lists the archives stored for a device, newest first.
func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	dev := s.device(r.PathValue("name"))
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such device: " + r.PathValue("name")})
		return
	}
	type view struct {
		File     string    `json:"file"`
		Size     int64     `json:"size"`
		Modified time.Time `json:"modified"`
	}
	views := []view{}
	entries, err := os.ReadDir(s.deviceDataDir(dev.Name))
	if err != nil && !os.IsNotExist(err) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			views = append(views, view{File: e.Name(), Size: info.Size(), Modified: info.ModTime().UTC()})
		}
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Modified.After(views[j].Modified) })
	writeJSON(w, http.StatusOK, map[string]any{"device": dev.Name, "backups": views})
}
