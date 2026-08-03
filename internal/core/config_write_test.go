package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config file with comments, a server block, and two devices — enough to
// prove that editing one entry leaves everything else (comments, key order,
// the other device) untouched.
const seedConfig = `# my fleet
server:
  listen: ":8080"
devices:
  # the good one
  - name: living-room
    host: 192.0.2.20
    username: admin
    password: "s3cret"
  - name: kitchen
    host: 192.0.2.21
    username: admin
`

func writeSeed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(seedConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func backupCount(t *testing.T, path string) int {
	t.Helper()
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

func TestAddDevice(t *testing.T) {
	path := writeSeed(t)
	cfg, err := AddDevice(path, Device{
		Name: "garage", Host: "192.0.2.2", Username: "admin", Password: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Devices) != 3 {
		t.Fatalf("devices = %d, want 3", len(cfg.Devices))
	}
	// On-disk file reloads and has the new device.
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if deviceByName(reloaded, "garage") == nil {
		t.Error("garage not persisted")
	}
	// Comments and the untouched device survive.
	out := readFile(t, path)
	for _, want := range []string{"# my fleet", "# the good one", "kitchen"} {
		if !strings.Contains(out, want) {
			t.Errorf("edited file lost %q:\n%s", want, out)
		}
	}
	if backupCount(t, path) != 1 {
		t.Errorf("want exactly one backup, got %d", backupCount(t, path))
	}
}

func TestAddDeviceDuplicateRejected(t *testing.T) {
	path := writeSeed(t)
	before := readFile(t, path)
	if _, err := AddDevice(path, Device{Name: "kitchen", Host: "h", Username: "u"}); err == nil {
		t.Fatal("expected duplicate-name error")
	}
	if readFile(t, path) != before {
		t.Error("file changed despite rejected add")
	}
	if backupCount(t, path) != 0 {
		t.Error("no backup should be written for a rejected edit")
	}
}

func TestRemoveDevice(t *testing.T) {
	path := writeSeed(t)
	cfg, err := RemoveDevice(path, "kitchen")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Devices) != 1 || deviceByName(cfg, "kitchen") != nil {
		t.Fatalf("kitchen not removed: %+v", cfg.Devices)
	}
	out := readFile(t, path)
	if strings.Contains(out, "kitchen") {
		t.Errorf("kitchen still on disk:\n%s", out)
	}
	if !strings.Contains(out, "living-room") {
		t.Error("removed the wrong device")
	}
}

func TestRemoveDeviceNotFound(t *testing.T) {
	path := writeSeed(t)
	before := readFile(t, path)
	if _, err := RemoveDevice(path, "nope"); err == nil {
		t.Fatal("expected not-found error")
	}
	if readFile(t, path) != before {
		t.Error("file changed despite failed remove")
	}
}

func TestRemoveLastDeviceAllowed(t *testing.T) {
	// An empty inventory is valid (you adopt devices from the UI), so removing
	// the last device must succeed and leave a device-less config on disk.
	path := writeSeed(t)
	if _, err := RemoveDevice(path, "kitchen"); err != nil {
		t.Fatal(err)
	}
	cfg, err := RemoveDevice(path, "living-room")
	if err != nil {
		t.Fatalf("removing the last device should be allowed: %v", err)
	}
	if len(cfg.Devices) != 0 {
		t.Fatalf("want empty inventory, got %d", len(cfg.Devices))
	}
	if reloaded, err := LoadConfig(path); err != nil || len(reloaded.Devices) != 0 {
		t.Fatalf("empty config must reload cleanly: %v %v", reloaded, err)
	}
}

func TestUpdateDevice(t *testing.T) {
	path := writeSeed(t)
	_, err := UpdateDevice(path, "living-room", Device{
		Name: "living-room", Host: "192.0.2.30", Username: "admin", Password: "new",
		Desired: Desired{SSIDs: []SSID{{Name: "Net", Security: "wpa2-psk", Passphrase: "p"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	d := deviceByName(reloaded, "living-room")
	if d == nil || d.Host != "192.0.2.30" || len(d.Desired.SSIDs) != 1 {
		t.Fatalf("update not applied: %+v", d)
	}
	// The other device and comments are still there.
	out := readFile(t, path)
	if !strings.Contains(out, "kitchen") || !strings.Contains(out, "# my fleet") {
		t.Errorf("update disturbed the rest of the file:\n%s", out)
	}
}

func TestUpdateDeviceRename(t *testing.T) {
	path := writeSeed(t)
	if _, err := UpdateDevice(path, "kitchen", Device{
		Name: "pantry", Host: "192.0.2.21", Username: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if deviceByName(reloaded, "kitchen") != nil || deviceByName(reloaded, "pantry") == nil {
		t.Errorf("rename failed: %+v", reloaded.Devices)
	}
}

func TestUpdateDeviceRenameCollision(t *testing.T) {
	path := writeSeed(t)
	before := readFile(t, path)
	// Rename kitchen -> living-room collides with the existing device.
	if _, err := UpdateDevice(path, "kitchen", Device{
		Name: "living-room", Host: "h", Username: "u",
	}); err == nil {
		t.Fatal("expected collision error")
	}
	if readFile(t, path) != before {
		t.Error("file changed despite rejected rename")
	}
}

func TestUpdateDeviceNotFound(t *testing.T) {
	path := writeSeed(t)
	if _, err := UpdateDevice(path, "ghost", Device{Name: "ghost", Host: "h", Username: "u"}); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestAddDeviceToEmptyFile(t *testing.T) {
	// A brand-new (empty) file should get a devices list created for it.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := AddDevice(path, Device{Name: "a", Host: "h", Username: "u"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Devices) != 1 {
		t.Fatalf("devices = %d", len(cfg.Devices))
	}
}

func deviceByName(cfg *Config, name string) *Device {
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// The dashboard is never sent a declared passphrase, so it cannot echo one
// back. An update that leaves it blank must keep the stored one rather than
// silently wiping the network's key out of the config.
func TestUpdatePreservesSSIDPassphraseWhenBlank(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := "devices:\n  - name: ap1\n    host: 192.0.2.20\n    username: admin\n" +
		"    desired:\n      ssids:\n        - name: HomeNet\n          passphrase: stored-key\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := UpdateDevice(path, "ap1", Device{
		Name: "ap1", Host: "192.0.2.21", Username: "admin",
		Desired: Desired{SSIDs: []SSID{{Name: "HomeNet", VLAN: 7}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Devices[0].Desired.SSIDs[0].Passphrase; got != "stored-key" {
		t.Errorf("passphrase should be preserved, got %q", got)
	}
	if got := cfg.Devices[0].Desired.SSIDs[0].VLAN; got != 7 {
		t.Errorf("the rest of the edit must still apply, vlan = %d", got)
	}

	// An explicit passphrase replaces it.
	cfg, err = UpdateDevice(path, "ap1", Device{
		Name: "ap1", Host: "192.0.2.21", Username: "admin",
		Desired: Desired{SSIDs: []SSID{{Name: "HomeNet", Passphrase: "new-key"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Devices[0].Desired.SSIDs[0].Passphrase; got != "new-key" {
		t.Errorf("explicit passphrase should replace, got %q", got)
	}
}

// A passphrase stored as ${VAR} must survive a blank-passphrase edit as a
// reference, not be written back as the expanded secret.
func TestUpdateKeepsEnvRefSSIDPassphrase(t *testing.T) {
	t.Setenv("SSID_KEY_TEST", "real-wifi-key")
	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := "devices:\n  - name: ap1\n    host: 192.0.2.20\n    username: admin\n" +
		"    desired:\n      ssids:\n        - name: HomeNet\n          passphrase: \"${SSID_KEY_TEST}\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := UpdateDevice(path, "ap1", Device{
		Name: "ap1", Host: "192.0.2.20", Username: "admin",
		Desired: Desired{SSIDs: []SSID{{Name: "HomeNet", VLAN: 3}}},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "real-wifi-key") {
		t.Fatalf("the expanded passphrase leaked into the config file:\n%s", raw)
	}
	if !strings.Contains(string(raw), "${SSID_KEY_TEST}") {
		t.Fatalf("the ${VAR} reference must survive verbatim:\n%s", raw)
	}
}
