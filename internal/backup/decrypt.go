// Package backup handles the WAX610's encrypted configuration archives:
// decrypting them to the plaintext config tar, and building a readable,
// diffable history of how a device's configuration changed over time.
//
// The archive format was reverse-engineered from the firmware's own
// /usr/sbin/file_enc (libgcrypt). A native Go decryptor was verified to match
// the vendor binary byte-for-byte across every available real backup, so no
// vendor binary or emulator is needed at runtime. Layout:
//
//	[ salt: 128 ][ IV: 16 ][ ciphertext: AES-256-CBC ][ HMAC-SHA512: 64 ]
//
//	derived = PBKDF2-HMAC-SHA512(password, salt, iter=10000, dkLen=96)
//	aesKey  = derived[0:32]      // AES-256
//	macKey  = derived[32:96]
//	tag     = HMAC-SHA512(macKey, salt || IV || ciphertext)   // == trailing 64
//
// The password is the device's admin password — the same one selfsight already
// holds to talk to the AP. The plaintext is the device's config tar; it is
// never padded (a tar is already block-aligned).
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"errors"
	"fmt"
)

const (
	saltLen    = 128
	ivLen      = 16
	macLen     = 64
	iterations = 10000
	dkLen      = 96 // 32-byte AES key + 64-byte HMAC key
	minLen     = saltLen + ivLen + macLen
)

// ErrBadPassword means the archive's authentication tag did not match — the
// password is wrong or the file is corrupt. It is returned before any
// decryption is attempted, so a wrong password never yields garbage plaintext.
var ErrBadPassword = errors.New("backup: wrong password or corrupt archive (HMAC mismatch)")

// Decrypt turns an encrypted WAX610 config archive into the plaintext config
// tar, using the device's admin password. The archive is authenticated before
// decryption: a wrong password fails with ErrBadPassword rather than returning
// meaningless bytes.
func Decrypt(archive []byte, password string) ([]byte, error) {
	if len(archive) < minLen {
		return nil, fmt.Errorf("backup: archive too small (%d bytes)", len(archive))
	}
	salt := archive[:saltLen]
	iv := archive[saltLen : saltLen+ivLen]
	ct := archive[saltLen+ivLen : len(archive)-macLen]
	tag := archive[len(archive)-macLen:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("backup: ciphertext not block-aligned (%d bytes)", len(ct))
	}

	derived, err := pbkdf2.Key(sha512.New, password, salt, iterations, dkLen)
	if err != nil {
		return nil, fmt.Errorf("backup: key derivation: %w", err)
	}
	aesKey, macKey := derived[:32], derived[32:96]

	mac := hmac.New(sha512.New, macKey)
	mac.Write(salt)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, ErrBadPassword
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("backup: cipher: %w", err)
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return pt, nil
}
