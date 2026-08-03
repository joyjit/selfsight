package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

// Encrypt produces a WAX610 config archive from plaintext (the device config
// tar) and the admin password, in the exact format the AP's own restore path
// accepts. It is the inverse of Decrypt and uses the same primitives:
//
//	[salt:128][IV:16][AES-256-CBC ciphertext][HMAC-SHA512:64]
//
// salt and IV are random per call (as the firmware does), so two encryptions of
// the same plaintext differ — that is correct for authenticated encryption.
// The plaintext must be a whole number of AES blocks (a tar always is); this is
// enforced rather than padded, so a re-encrypt of a decrypted backup is
// byte-reversible.
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	var salt [saltLen]byte
	var iv [ivLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv[:]); err != nil {
		return nil, err
	}
	return encryptWith(plaintext, password, salt[:], iv[:])
}

// encryptWith is Encrypt with caller-supplied salt and IV. Exposed to tests so a
// decrypted backup can be re-encrypted with its original salt/IV and compared
// byte-for-byte against the vendor's output — the strongest correctness check.
func encryptWith(plaintext []byte, password string, salt, iv []byte) ([]byte, error) {
	if len(salt) != saltLen || len(iv) != ivLen {
		return nil, fmt.Errorf("backup: salt must be %d and IV %d bytes", saltLen, ivLen)
	}
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("backup: plaintext not block-aligned (%d bytes)", len(plaintext))
	}
	derived, err := pbkdf2.Key(sha512.New, password, salt, iterations, dkLen)
	if err != nil {
		return nil, fmt.Errorf("backup: key derivation: %w", err)
	}
	aesKey, macKey := derived[:32], derived[32:96]

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("backup: cipher: %w", err)
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plaintext)

	mac := hmac.New(sha512.New, macKey)
	mac.Write(salt)
	mac.Write(iv)
	mac.Write(ct)
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(salt)+len(iv)+len(ct)+len(tag))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, tag...)
	return out, nil
}
