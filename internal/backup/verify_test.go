package backup

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestIsTar(t *testing.T) {
	enc, err := os.ReadFile("testdata/backup-fixture.enc")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := os.ReadFile("testdata/backup-fixture.plain.tar")
	if err != nil {
		t.Fatal(err)
	}
	if IsTar(enc) {
		t.Error("encrypted archive misdetected as tar")
	}
	if !IsTar(plain) {
		t.Error("plain tar not detected")
	}
	if IsTar([]byte("short")) {
		t.Error("tiny input misdetected as tar")
	}
}

func TestVerifyRoundTrip(t *testing.T) {
	enc, err := os.ReadFile("testdata/backup-fixture.enc")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/backup-fixture.plain.tar")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := VerifyRoundTrip(enc, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, want) {
		t.Error("round-trip-verified plaintext differs from known plaintext")
	}
	if _, err := VerifyRoundTrip(enc, "wrong-password"); !errors.Is(err, ErrBadPassword) {
		t.Errorf("wrong password: want ErrBadPassword, got %v", err)
	}
}

func TestMember(t *testing.T) {
	plain := buildFixtureTar(t, "cfg-line x\n", "shadow-line\n")
	shadow, err := Member(plain, ShadowPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(shadow) != "shadow-line\n" {
		t.Errorf("shadow member = %q", shadow)
	}
	if _, err := Member(plain, "no/such/file"); !errors.Is(err, ErrMemberMissing) {
		t.Errorf("missing member: want ErrMemberMissing, got %v", err)
	}
}
