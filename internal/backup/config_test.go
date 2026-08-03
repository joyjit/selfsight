package backup

import (
	"os"
	"strings"
	"testing"
)

func TestExtractAndRedactFixture(t *testing.T) {
	enc, _ := os.ReadFile("testdata/backup-fixture.enc")
	plain, err := Decrypt(enc, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	red, err := RedactedConfig(plain)
	if err != nil {
		t.Fatal(err)
	}
	s := string(red)

	// The fake presharedKey value must NOT survive; its key must, with a marker.
	if strings.Contains(s, "fake-passphrase-not-real") {
		t.Error("secret value leaked into redacted config")
	}
	if !strings.Contains(s, "presharedKey «redacted:") {
		t.Errorf("presharedKey not redacted:\n%s", s)
	}
	// Non-secret settings pass through so they can be diffed.
	for _, want := range []string{"apName TestAP", "wlan0:channel 6", "ssid TestNet"} {
		if !strings.Contains(s, want) {
			t.Errorf("expected %q in redacted config:\n%s", want, s)
		}
	}
}

func TestRedactIsStableButChangeSensitive(t *testing.T) {
	a := Redact([]byte("system:x:presharedKey secret-one\nsystem:x:ssid Net\n"))
	b := Redact([]byte("system:x:presharedKey secret-one\nsystem:x:ssid Net\n"))
	c := Redact([]byte("system:x:presharedKey secret-TWO\nsystem:x:ssid Net\n"))
	if string(a) != string(b) {
		t.Error("redaction not stable for identical input")
	}
	if string(a) == string(c) {
		t.Error("a changed secret should change its fingerprint")
	}
}
