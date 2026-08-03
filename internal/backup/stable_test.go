package backup

import (
	"strings"
	"testing"
)

func TestStableConfig(t *testing.T) {
	blobA := strings.Repeat("a", 127)
	blobB := strings.Repeat("b", 127)
	cfg := "system:basicSettings:apName Home\n" +
		"system:vapSettings:vapSettingTable:wlan0:vap0:ssid Guest\n" +
		"system:vapSettings:vapSettingTable:wlan0:vap0:presharedKey " + blobA + "\n" +
		"system:radSec:priRadServerSharedKey " + blobB + "\n" +
		"system:vapSettings:vapSettingTable:wlan0:vap0:vlan 10\n" +
		"system:info:shortHex deadbeef\n"

	got := string(StableConfig([]byte(cfg)))

	// Both encrypted blobs collapse to the same fixed placeholder, regardless
	// of their (differing) ciphertext — that is what kills reboot churn.
	if strings.Count(got, "«encrypted»") != 2 {
		t.Fatalf("want 2 normalized secrets, got:\n%s", got)
	}
	if strings.Contains(got, blobA) || strings.Contains(got, blobB) {
		t.Error("ciphertext must not survive into history")
	}
	// Keys stay, so an added/removed secret still shows.
	for _, k := range []string{"vap0:presharedKey «encrypted»", "priRadServerSharedKey «encrypted»"} {
		if !strings.Contains(got, k) {
			t.Errorf("key must be kept: %q missing", k)
		}
	}
	// Structure and short hex are untouched.
	for _, keep := range []string{"apName Home", "ssid Guest", "vlan 10", "shortHex deadbeef"} {
		if !strings.Contains(got, keep) {
			t.Errorf("non-secret line altered: %q missing", keep)
		}
	}
}

// The same plaintext secret re-wrapped to different ciphertext (what a reboot
// does) must produce an identical history view — no diff.
func TestStableConfigSuppressesRewrapChurn(t *testing.T) {
	line := "system:vapSettings:vapSettingTable:wlan0:vap0:presharedKey "
	before := StableConfig([]byte(line + strings.Repeat("1", 127) + "\n"))
	after := StableConfig([]byte(line + strings.Repeat("2", 127) + "\n"))
	if string(before) != string(after) {
		t.Errorf("re-wrapped secret still churns:\n%s\nvs\n%s", before, after)
	}
}

// Self-updating bookkeeping timestamps (the AP noting when it last checked
// for firmware) are not config changes: they must not churn the history view
// or trigger change-detected backups.
func TestStableConfigSuppressesBookkeepingChurn(t *testing.T) {
	line := "system:FwUpdate:LastcheckedDate "
	before := StableConfig([]byte(line + `Sun\ Jul\ 19\ 00\:00\:00 PDT\ 2026` + "\n"))
	after := StableConfig([]byte(line + `Sun\ Jul\ 19\ 08\:33\:53 PDT\ 2026` + "\n"))
	if string(before) != string(after) {
		t.Errorf("bookkeeping timestamp still churns:\n%s\nvs\n%s", before, after)
	}
}

// Snapshots recorded before StableConfig blanked bookkeeping still carry real
// timestamp values — the diff must hide those lines too.
func TestDiffHidesBookkeeping(t *testing.T) {
	from := "system:FwUpdate:LastcheckedDate a\nsystem:w0:channel 6\n"
	to := "system:FwUpdate:LastcheckedDate b\nsystem:w0:channel 11\n"
	d := unifiedDiff(from, to)
	if strings.Contains(d, "Lastchecked") {
		t.Errorf("bookkeeping line leaked into diff:\n%s", d)
	}
	if !strings.Contains(d, "~ w0:channel 6 → 11") {
		t.Errorf("real change missing from diff:\n%s", d)
	}
}
