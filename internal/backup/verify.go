package backup

import (
	"bytes"
	"errors"
)

// A stored backup is either a plain tar (the decrypted form selfsight keeps)
// or the AP's encrypted blob (what the device hands out, and what old versions
// of selfsight stored). The two are told apart by the tar magic — an encrypted
// blob is ciphertext at that offset, so the marker cannot appear by design.

// tar magic: "ustar" at byte 257 of the first header block.
const tarMagicOffset = 257

// IsTar reports whether data is a plain (decrypted) tar archive.
func IsTar(data []byte) bool {
	return len(data) > tarMagicOffset+5 &&
		bytes.Equal(data[tarMagicOffset:tarMagicOffset+5], []byte("ustar"))
}

// ErrRoundTrip means the decrypted bytes, re-encrypted with the archive's own
// salt and IV, did not reproduce the original archive byte for byte. That
// should be impossible for a genuine AP archive and the right password — if it
// happens, the safe move is to keep the encrypted original, which this error
// signals.
var ErrRoundTrip = errors.New("backup: decrypt/re-encrypt round trip did not reproduce the archive")

// VerifyRoundTrip decrypts an encrypted archive and PROVES the decryption is
// faithful before anyone throws the encrypted form away: the plaintext is
// re-encrypted with the archive's own salt and IV and must reproduce the
// original byte for byte. Only then is the plaintext returned. This is the
// gate that makes it safe to store backups decrypted — a decrypted copy that
// passes this check can always be turned back into a valid archive.
func VerifyRoundTrip(enc []byte, password string) ([]byte, error) {
	plain, err := Decrypt(enc, password)
	if err != nil {
		return nil, err
	}
	re, err := encryptWith(plain, password, enc[:saltLen], enc[saltLen:saltLen+ivLen])
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(re, enc) {
		return nil, ErrRoundTrip
	}
	return plain, nil
}
