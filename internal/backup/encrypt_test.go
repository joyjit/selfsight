package backup

import (
	"bytes"
	"os"
	"testing"
)

// Re-encrypting the fixture's plaintext with the fixture's own salt+IV must
// reproduce the committed archive byte-for-byte — the inverse of
// TestDecryptMatchesFixture, freezing the encryptor's output the same way.
func TestEncryptReproducesFixture(t *testing.T) {
	enc, err := os.ReadFile("testdata/backup-fixture.enc")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(enc, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	salt := enc[:saltLen]
	iv := enc[saltLen : saltLen+ivLen]
	re, err := encryptWith(plain, fixturePassword, salt, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(re, enc) {
		t.Fatalf("re-encrypt not byte-identical to vendor fixture (%d vs %d)", len(re), len(enc))
	}
}

// Encrypt with fresh random salt/IV must always decrypt back to the plaintext,
// and two encryptions of the same input must differ (random salt/IV).
func TestEncryptRandomRoundTrip(t *testing.T) {
	enc, _ := os.ReadFile("testdata/backup-fixture.enc")
	plain, err := Decrypt(enc, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Encrypt(plain, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(plain, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two encryptions were identical — salt/IV not random")
	}
	for _, c := range [][]byte{a, b} {
		back, err := Decrypt(c, fixturePassword)
		if err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("round-trip failed: err=%v equal=%v", err, bytes.Equal(back, plain))
		}
	}
}

func TestEncryptRejectsUnalignedPlaintext(t *testing.T) {
	if _, err := Encrypt([]byte("not-16-aligned"), "pw"); err == nil {
		t.Fatal("expected error for non-block-aligned plaintext")
	}
}
