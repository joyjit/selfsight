package backup

import (
	"archive/tar"
	"bytes"
	"testing"
)

// The committed fixture pair in testdata/ is fully synthetic (fake config,
// fake shadow, fake keys — see buildFixtureTar for the member list), and the
// .enc side is produced by this package's own Encrypt. So the tests it feeds
// FREEZE current behaviour: any change to the format constants or steps
// changes the bytes and fails them. They do NOT independently prove agreement
// with NETGEAR's on-wire format.
//
// That agreement was established separately and is not re-checked here: the
// native decryptor was verified byte-for-byte against the vendor binary on
// 9/9 real device backups (see decrypt.go and DESIGN.md, "Backup decryption").
// Real backups carry live configs and password hashes, so none can be
// committed. To restore an in-CI vendor check, rebuild the .enc with the
// firmware's own file_enc under qemu and update this comment.
//
// Password: fixturePassword.

// buildFixtureTar assembles a synthetic decrypted backup with the members a
// real WAX backup carries: the config, the login password hashes (shadow), and
// the decryptedKeys marker the AP requires on restore. Every value is fake.
func buildFixtureTar(t *testing.T, config, shadow string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range []struct{ name, body string }{
		{ConfigPath, config},
		{ShadowPath, shadow},
		{DecryptedKeysPath, "fake-decrypted-keys\n"},
	} {
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
