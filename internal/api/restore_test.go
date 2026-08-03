package api

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"selfsight/internal/backup"
)

// mkBackupTar builds an in-memory decrypted backup with the members a real
// one has. withKeys=false simulates a truncated/foreign archive the AP would
// reject.
func mkBackupTar(t *testing.T, config, shadow string, withKeys bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	members := []struct{ name, body string }{
		{backup.ConfigPath, config},
		{backup.ShadowPath, shadow},
	}
	if withKeys {
		members = append(members, struct{ name, body string }{backup.DecryptedKeysPath, "keys\n"})
	}
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o600, Size: int64(len(m.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// restoreFake is a fake AP for the full restore flow: it serves logins, an
// encrypted backup download, and a restore upload; once the upload lands,
// every signed read answers 401 — the session-reset signal a real reboot
// produces.
type restoreFake struct {
	mu       sync.Mutex
	enc      []byte // what /wac510-backup serves
	rebooted bool
	uploads  int
	uploaded []byte
}

func (f *restoreFake) server() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/AP_login":
			http.SetCookie(w, &http.Cookie{Name: "lhttpdsid", Value: "seed", HttpOnly: true})
		case r.URL.Path == "/restoreSettings":
			_ = r.ParseMultipartForm(4 << 20)
			file, _, err := r.FormFile("file")
			if err == nil {
				f.uploaded, _ = io.ReadAll(file)
				_ = file.Close()
			}
			f.uploads++
			f.rebooted = true
			_, _ = io.WriteString(w, `{"status":1}`) // response is never trusted anyway
		case r.URL.Path == "/wac510-backup":
			w.Header().Set("Content-Disposition", `attachment; filename="WAX610-AP-Test-config.tar"`)
			_, _ = w.Write(f.enc)
		case r.URL.Path == "/LogFile":
			_, _ = io.WriteString(w, `{"status":0}`)
		default:
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), "adminPasswd"):
				_, _ = io.WriteString(w, `{"status":0,"system":{"security_token":"tok"}}`)
			case f.rebooted, r.Header.Get("security") == "":
				_, _ = io.WriteString(w, `{"status":401}`)
			default:
				_, _ = io.WriteString(w, `{"status":0,"system":{"monitor":{"sysSerialNumber":"S1","sysVersion":"V9"},"basicSettings":{"apName":"AP","cloudStatus":"0"}}}`)
			}
		}
	}))
}

// The shadow member is present but no longer drives the revert check (it
// re-salts on every reboot); the admin credential in the config does.
const testShadow = "admin:$5$aaa$hashhashhash:19000:0:99999:7:::\n"

// cfgWithAdmin builds a config carrying the web-admin login the revert guard
// compares — the same fields a real backup has. passwdHash distinguishes a
// same-password snapshot from a rolled-back one.
func cfgWithAdmin(passwdHash string) string {
	return "system:basicSettings:apName AP\n" +
		"system:basicSettings:adminName admin\n" +
		"system:basicSettings:adminPasswd " + passwdHash + "\n"
}

const liveAdminHash = "$5$live$livehashvalue"
const oldAdminHash = "$5$old$oldhashvalue"

// restoreServer wires a Server to a restoreFake whose live device's config
// carries the current admin login, and stores snapshot (a decrypted tar) as
// snap.tar for ap1.
func restoreServer(t *testing.T, snapshot []byte) (*Server, *restoreFake) {
	t.Helper()
	fake := &restoreFake{}
	enc, err := backup.Encrypt(mkBackupTar(t, cfgWithAdmin(liveAdminHash), testShadow, true), "pw")
	if err != nil {
		t.Fatal(err)
	}
	fake.enc = enc
	ts := fake.server()
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)
	dir := s.deviceDataDir("ap1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snap.tar"), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	return s, fake
}

func postRestore(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/devices/ap1/restore", strings.NewReader(body)))
	return rr
}

// A snapshot whose shadow differs from the device's must be refused until the
// caller explicitly accepts that the admin password will roll back — and the
// AP must not have been touched with an upload.
func TestRestoreRefusesPasswordRevertWithoutConsent(t *testing.T) {
	snap := mkBackupTar(t, cfgWithAdmin(oldAdminHash), testShadow, true)
	s, fake := restoreServer(t, snap)

	rr := postRestore(t, s, `{"file":"snap.tar"}`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"passwordReverts":true`) {
		t.Fatalf("want 409 with passwordReverts, got %d: %s", rr.Code, rr.Body.String())
	}
	if fake.uploads != 0 {
		t.Error("no archive may reach the AP before the revert is accepted")
	}

	rr = postRestore(t, s, `{"file":"snap.tar","acceptPasswordRevert":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("accepted revert must proceed, got %d: %s", rr.Code, rr.Body.String())
	}
	var got struct{ Rebooted, PasswordReverted bool }
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Rebooted || !got.PasswordReverted {
		t.Errorf("want rebooted+passwordReverted, got %+v", got)
	}
}

// A same-password snapshot restores without any consent dance, the upload is
// the snapshot re-encrypted with the current admin password (the AP decrypts
// it with the password header), and the pre-restore backup lands on disk in
// decrypted stored form.
func TestRestoreReencryptsWithCurrentPassword(t *testing.T) {
	snap := mkBackupTar(t, cfgWithAdmin(liveAdminHash), testShadow, true)
	s, fake := restoreServer(t, snap)

	rr := postRestore(t, s, `{"file":"snap.tar"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"passwordReverted":true`) {
		t.Error("same admin credential must not be reported as a password revert")
	}

	// The uploaded bytes must decrypt — with the CURRENT password — back to
	// exactly the stored snapshot.
	plain, err := backup.Decrypt(fake.uploaded, "pw")
	if err != nil {
		t.Fatalf("upload does not decrypt with the current admin password: %v", err)
	}
	if !bytes.Equal(plain, snap) {
		t.Error("upload is not the stored snapshot")
	}

	// Hard rule: the restore took a fresh backup first, stored decrypted.
	entries, err := os.ReadDir(s.deviceDataDir("ap1"))
	if err != nil {
		t.Fatal(err)
	}
	foundFresh := false
	for _, e := range entries {
		if e.Name() == "snap.tar" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.deviceDataDir("ap1"), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if backup.IsTar(data) {
			foundFresh = true
		}
	}
	if !foundFresh {
		t.Error("pre-restore backup missing or not stored decrypted")
	}
}

// An archive that never decrypted (password unknown) must be refused before
// anything touches the AP, as must one that is not a complete AP backup.
func TestRestoreRefusesBadArchives(t *testing.T) {
	undecryptable, err := backup.Encrypt(mkBackupTar(t, cfgWithAdmin(liveAdminHash), testShadow, true), "some-old-password")
	if err != nil {
		t.Fatal(err)
	}
	s, fake := restoreServer(t, undecryptable)
	rr := postRestore(t, s, `{"file":"snap.tar"}`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "still encrypted") {
		t.Fatalf("want 409 for undecryptable archive, got %d: %s", rr.Code, rr.Body.String())
	}
	if fake.uploads != 0 {
		t.Error("undecryptable archive must never reach the AP")
	}

	incomplete := mkBackupTar(t, cfgWithAdmin(liveAdminHash), testShadow, false)
	s2, fake2 := restoreServer(t, incomplete)
	rr = postRestore(t, s2, `{"file":"snap.tar"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for incomplete archive, got %d: %s", rr.Code, rr.Body.String())
	}
	if fake2.uploads != 0 {
		t.Error("incomplete archive must never reach the AP")
	}
}

// The scheduler must store fresh backups decrypted (round-trip proven) and
// record their config in history — the whole point of the storage redesign.
func TestScheduledBackupStoredDecryptedWithHistory(t *testing.T) {
	fake := &restoreFake{}
	plain := mkBackupTar(t, "system:basicSettings:apName TestAP\n", testShadow, true)
	enc, err := backup.Encrypt(plain, "pw")
	if err != nil {
		t.Fatal(err)
	}
	fake.enc = enc
	ts := fake.server()
	t.Cleanup(ts.Close)
	s := schedulerServer(t, ts)

	s.backupRound(t.Context())

	entries, err := os.ReadDir(s.deviceDataDir("ap1"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("want exactly one stored backup, got %v (err %v)", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(s.deviceDataDir("ap1"), entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, plain) {
		t.Error("stored backup is not the decrypted archive")
	}

	snaps, err := s.history.History("ap1")
	if err != nil || len(snaps) != 1 {
		t.Fatalf("want one history snapshot, got %v (err %v)", snaps, err)
	}
	diff, _, err := s.history.Diff("ap1", "", snaps[0].Commit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff, "apName TestAP") {
		t.Errorf("history must hold the full config, diff: %s", diff)
	}
}
