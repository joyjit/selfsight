package backup

import (
	"strings"
	"testing"
	"time"
)

func TestHistoryRecordsAndDiffs(t *testing.T) {
	h, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 7, 1, 4, 0, 0, 0, time.UTC)
	t1 := t0.Add(24 * time.Hour)

	v1 := Redact([]byte("system:x:ssid Net\nsystem:x:presharedKey aaa\nsystem:w0:channel 6\n"))
	if ok, err := h.Record("GarageAP", v1, t0, "first"); err != nil || !ok {
		t.Fatalf("record v1: ok=%v err=%v", ok, err)
	}
	// Identical content must not create a second commit.
	if ok, _ := h.Record("GarageAP", v1, t0, "dup"); ok {
		t.Fatal("identical snapshot should not commit")
	}
	// A change: channel 6 -> 11, and the passphrase rotates.
	v2 := Redact([]byte("system:x:ssid Net\nsystem:x:presharedKey bbb\nsystem:w0:channel 11\n"))
	if ok, err := h.Record("GarageAP", v2, t1, "changed"); err != nil || !ok {
		t.Fatalf("record v2: ok=%v err=%v", ok, err)
	}

	hist, err := h.History("GarageAP")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("want 2 snapshots, got %d", len(hist))
	}
	if !hist[0].When.After(hist[1].When) {
		t.Error("history not newest-first")
	}

	diff, _, err := h.Diff("GarageAP", hist[1].Commit, hist[0].Commit)
	if err != nil {
		t.Fatal(err)
	}
	// A changed setting reads old → new on one line (leading "system:"
	// dropped); the unchanged ssid line does not appear.
	if !strings.Contains(diff, "~ w0:channel 6 → 11") {
		t.Errorf("diff should pair the channel change as old → new:\n%s", diff)
	}
	if strings.Contains(diff, "ssid Net") {
		t.Errorf("unchanged line should not be in diff:\n%s", diff)
	}
	// The passphrase changed but the plaintext never appears — only fingerprints.
	if strings.Contains(diff, "aaa") || strings.Contains(diff, "bbb") {
		t.Errorf("secret leaked into diff:\n%s", diff)
	}
	if !strings.Contains(diff, "presharedKey «redacted:") {
		t.Errorf("expected redacted passphrase change in diff:\n%s", diff)
	}
}

func TestHistoryEmpty(t *testing.T) {
	h, err := OpenHistory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.History("Nobody")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty history, got %d", len(got))
	}
}
