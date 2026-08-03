package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodConfig = `
server:
  listen: ":9090"
devices:
  - name: living-room
    host: 192.0.2.20
    model: WAX610
    username: admin
    password: "s3cret"
    desired:
      ssids:
        - name: HomeNet
          vlan: 1
          security: wpa2-psk
          passphrase: "also-s3cret"
      radios:
        2g: { channel: auto, power: full }
        5g: { channel: "44",  power: full }
`

func TestLoadGoodConfig(t *testing.T) {
	cfg, err := parseConfig([]byte(goodConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != ":9090" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if len(cfg.Devices) != 1 {
		t.Fatalf("devices = %d", len(cfg.Devices))
	}
	d := cfg.Devices[0]
	if d.Name != "living-room" || d.Host != "192.0.2.20" {
		t.Errorf("device = %+v", d)
	}
	if len(d.Desired.SSIDs) != 1 || d.Desired.SSIDs[0].Name != "HomeNet" {
		t.Errorf("ssids = %+v", d.Desired.SSIDs)
	}
	if d.Desired.Radios["5g"].Channel != "44" {
		t.Errorf("5g channel = %q", d.Desired.Radios["5g"].Channel)
	}
}

func TestDefaultListen(t *testing.T) {
	cfg, err := parseConfig([]byte("devices:\n  - name: a\n    host: h\n    username: u\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Listen != DefaultListen {
		t.Errorf("want default listen, got %q", cfg.Server.Listen)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"missing host":   "devices:\n  - name: a\n    username: u\n",
		"missing name":   "devices:\n  - host: h\n    username: u\n",
		"missing user":   "devices:\n  - name: a\n    host: h\n",
		"duplicate name": "devices:\n  - name: a\n    host: h\n    username: u\n  - name: a\n    host: h2\n    username: u\n",
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConfig([]byte(cfg)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("WAX_PW", "s3cret-from-env")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("devices:\n  - name: a\n    host: h\n    username: u\n    password: ${WAX_PW}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devices[0].Password != "s3cret-from-env" {
		t.Fatalf("password = %q, want expanded value", cfg.Devices[0].Password)
	}
}

func TestEnvExpansionIgnoresComments(t *testing.T) {
	// A ${VAR} in a comment or on a commented-out line must NOT be expanded, so
	// an unset var mentioned only in comments doesn't crash startup.
	t.Setenv("REAL_PW", "ok")
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "" +
		"# passwords are ${DOC_ONLY_VAR} expanded from env\n" +
		"server:\n" +
		"  # auth:\n" +
		"  #   password: ${COMMENTED_AUTH_VAR}\n" +
		"devices:\n" +
		"  - name: a\n" +
		"    host: h\n" +
		"    username: u\n" +
		"    password: ${REAL_PW}  # inline note ${ALSO_IGNORED}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("comment-only ${VARS} must not error: %v", err)
	}
	if cfg.Devices[0].Password != "ok" {
		t.Fatalf("password = %q, want the expanded value", cfg.Devices[0].Password)
	}
}

func TestEnvExpansionUnsetErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("devices:\n  - name: a\n    host: h\n    username: u\n    password: ${DEFINITELY_UNSET_VAR}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "DEFINITELY_UNSET_VAR") {
		t.Fatalf("want error naming the unset var, got %v", err)
	}
}

func TestEnvExpansionSurvivesWrite(t *testing.T) {
	// Editing one device must leave another device's ${VAR} reference literal on
	// disk, while the returned in-memory config has it expanded.
	t.Setenv("A_PW", "aaa")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("devices:\n  - name: a\n    host: h\n    username: u\n    password: ${A_PW}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := AddDevice(path, Device{Name: "b", Host: "h2", Username: "u", Password: "plain"})
	if err != nil {
		t.Fatal(err)
	}
	// Returned config: a's password is expanded.
	if d := deviceByName(cfg, "a"); d == nil || d.Password != "aaa" {
		t.Fatalf("in-memory a.password = %v, want expanded", d)
	}
	// On disk: a's password is still the literal ${A_PW}.
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "${A_PW}") {
		t.Fatalf("on-disk config lost the ${A_PW} reference:\n%s", raw)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	bad := "devices:\n  - name: a\n    host: h\n    username: u\n    passwrod: oops\n"
	_, err := parseConfig([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "passwrod") {
		t.Errorf("expected unknown-field error naming the typo, got %v", err)
	}
}

// server.backups is deprecated: scheduled backups were removed (backups are now
// taken when a device's config changes). Because the loader is strict, a config
// that still carries the block must load — accepted and ignored — not fail.
func TestDeprecatedBackupsBlockAccepted(t *testing.T) {
	base := "devices:\n  - name: a\n    host: h\n    username: u\n"

	withBlock := "server:\n  backups:\n    every: 24h\n    keep: 14\n" + base
	if _, err := parseConfig([]byte(withBlock)); err != nil {
		t.Errorf("a legacy server.backups block must still load, got: %v", err)
	}

	// Even a value the old validator would have rejected is now simply ignored,
	// not an error — the field does nothing.
	loose := "server:\n  backups:\n    every: nonsense\n" + base
	if _, err := parseConfig([]byte(loose)); err != nil {
		t.Errorf("deprecated block is ignored, not validated, got: %v", err)
	}

	// Omitting it is of course fine.
	if _, err := parseConfig([]byte(base)); err != nil {
		t.Errorf("no backups block must load, got: %v", err)
	}
}

func TestBackupCheckDurations(t *testing.T) {
	// A nil block, or empty fields, yield the defaults.
	for _, bc := range []*BackupCheck{nil, {}} {
		s, i, err := bc.Durations()
		if err != nil || s != DefaultBackupStartupDelay || i != DefaultBackupInterval {
			t.Errorf("defaults expected, got %v/%v err=%v", s, i, err)
		}
	}

	// Valid values are parsed.
	if s, i, err := (&BackupCheck{StartupDelay: "30s", Interval: "2h"}).Durations(); err != nil || s != 30*time.Second || i != 2*time.Hour {
		t.Errorf("valid values: got %v/%v err=%v", s, i, err)
	}

	// Malformed, sub-minimum interval, or negative delay are errors — and still
	// hand back the safe defaults so an ignoring caller can't busy-loop.
	for _, bc := range []*BackupCheck{
		{Interval: "nonsense"},
		{Interval: "30s"}, // below the 1m floor
		{StartupDelay: "-5s"},
	} {
		s, i, err := bc.Durations()
		if err == nil {
			t.Errorf("want error for %+v", bc)
		}
		if s != DefaultBackupStartupDelay || i != DefaultBackupInterval {
			t.Errorf("error path must return defaults, got %v/%v for %+v", s, i, bc)
		}
	}

	// The validation is wired into config load.
	bad := "server:\n  backupCheck:\n    interval: 10s\n" +
		"devices:\n  - name: a\n    host: h\n    username: u\n"
	if _, err := parseConfig([]byte(bad)); err == nil {
		t.Error("a sub-minimum interval must fail config load")
	}
}

// TestDeviceNameMustBeASafePathElement pins the rule that keeps a device name
// from escaping the data directory. A name becomes a directory and file name
// (backups, status cache, event log, config history) and a REST path segment,
// so a separator or a "…/.." would let an inventory entry address any file the
// process can write.
func TestDeviceNameMustBeASafePathElement(t *testing.T) {
	bad := []string{
		"../evil",
		"../../etc/cron.d/x",
		"..",
		".",
		"a/b",
		`a\b`,
		".hidden",
		"has space",
		"",
		strings.Repeat("x", DeviceNameMax+1),
	}
	for _, name := range bad {
		if err := ValidateDeviceName(name); err == nil {
			t.Errorf("name %q should be rejected, was accepted", name)
		}
	}
	for _, name := range []string{"living-room", "ap1", "Garage_2", "ap.roof", strings.Repeat("x", DeviceNameMax)} {
		if err := ValidateDeviceName(name); err != nil {
			t.Errorf("name %q should be accepted: %v", name, err)
		}
	}
}

// A traversing name must be refused by config loading too, not only by the
// standalone validator — that is the boundary every name actually crosses.
func TestLoadRejectsTraversingDeviceName(t *testing.T) {
	cfg := "devices:\n  - name: ../../escape\n    host: 192.0.2.20\n    username: admin\n    password: pw\n"
	if _, err := parseConfig([]byte(cfg)); err == nil {
		t.Fatal("config with a traversing device name must fail to load")
	}
}
