package wax

import (
	"path/filepath"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "wax.json")

	// Missing file is not an error — it's a first run.
	got, err := LoadSession(path)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got.Valid() {
		t.Errorf("empty session should be invalid: %+v", got)
	}

	want := Session{Token: "tok", LHTTPDSID: "sid"}
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err = LoadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Valid() || got.Token != "tok" || got.LHTTPDSID != "sid" {
		t.Errorf("round-trip wrong: %+v", got)
	}
	if got.SavedAt.IsZero() {
		t.Error("SavedAt should be stamped on Save")
	}
}

// A saved session belongs to the host it was minted against. When the device
// entry is re-pointed at a different host, the manager must NOT replay the old
// cookie there — it discards it and would log in fresh instead.
func TestManagerDiscardsSessionSavedForAnotherHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sess.json")
	if err := (Session{Token: "tok", LHTTPDSID: "sid", Host: "192.0.2.211"}).Save(path); err != nil {
		t.Fatal(err)
	}

	if m := NewManager("192.0.2.211", path, "", ""); !m.hasSession {
		t.Error("session saved for the same host should be reused")
	}
	if m := NewManager("192.0.2.80", path, "", ""); m.hasSession {
		t.Error("session saved for another host must be discarded, not replayed")
	}
	// Legacy file with no recorded host: the path already ties it to the host.
	if err := (Session{Token: "tok", LHTTPDSID: "sid"}).Save(path); err != nil {
		t.Fatal(err)
	}
	if m := NewManager("192.0.2.80", path, "", ""); !m.hasSession {
		t.Error("legacy session without a recorded host should still be reused")
	}
}

// saveSession stamps the manager's host into the file, so the check above has
// something to compare on the next run.
func TestManagerSaveStampsHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sess.json")
	m := NewManager("192.0.2.80", path, "admin", "pw")
	m.SetSession("tok", "sid")
	got, err := LoadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "192.0.2.80" {
		t.Errorf("saved session should record its host, got %q", got.Host)
	}
}
