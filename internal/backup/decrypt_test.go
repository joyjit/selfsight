package backup

import (
	"archive/tar"
	"bytes"
	"os"
	"testing"
)

// The fixture is a synthetic config archive (fake, secret-free config)
// encrypted by this package's own Encrypt with the password below. Decrypting
// it must reproduce the committed plaintext tar exactly — that freezes the
// current format so any drift in the constants or steps fails loudly. See
// fixture_test.go for what this does and does not prove.
const fixturePassword = "testpassword123"

func TestDecryptMatchesFixture(t *testing.T) {
	enc, err := os.ReadFile("testdata/backup-fixture.enc")
	if err != nil {
		t.Fatal(err)
	}
	wantPlain, err := os.ReadFile("testdata/backup-fixture.plain.tar")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(enc, fixturePassword)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, wantPlain) {
		t.Fatalf("decrypted plaintext does not match committed fixture (%d vs %d bytes)", len(got), len(wantPlain))
	}
	// And it really is a readable tar with the config inside.
	tr := tar.NewReader(bytes.NewReader(got))
	h, err := tr.Next()
	if err != nil {
		t.Fatalf("decrypted output is not a tar: %v", err)
	}
	if h.Name != "sysconfig/config" {
		t.Errorf("first tar entry = %q, want sysconfig/config", h.Name)
	}
}

func TestDecryptWrongPasswordIsRejected(t *testing.T) {
	enc, err := os.ReadFile("testdata/backup-fixture.enc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(enc, "not-the-password"); err != ErrBadPassword {
		t.Fatalf("wrong password: got %v, want ErrBadPassword", err)
	}
}

func TestDecryptRejectsTooSmall(t *testing.T) {
	if _, err := Decrypt([]byte("tiny"), "x"); err == nil {
		t.Fatal("expected error for undersized archive")
	}
}
