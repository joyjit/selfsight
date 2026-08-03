package wax

import (
	"fmt"

	"selfsight/internal/backup"
	"selfsight/internal/device"
)

// Codec is the WAX implementation of device.Codec: the vendor's backup
// archive format and crypto, as pure functions over bytes. The mechanics live
// in internal/backup; this type is the vendor boundary in front of them.
type Codec struct{}

var _ device.Codec = Codec{}

func (Codec) IsEncrypted(data []byte) bool { return !backup.IsTar(data) }

func (Codec) Decrypt(data []byte, password string) ([]byte, error) {
	return backup.VerifyRoundTrip(data, password)
}

func (Codec) Encrypt(plain []byte, password string) ([]byte, error) {
	return backup.Encrypt(plain, password)
}

func (Codec) ValidateArchive(plain []byte) error {
	if _, err := backup.Member(plain, backup.DecryptedKeysPath); err != nil {
		return fmt.Errorf("not a complete AP backup (missing %s) — the AP would reject it", backup.DecryptedKeysPath)
	}
	return nil
}

func (Codec) AdminCredential(plain []byte) (string, error) {
	return backup.AdminCredential(plain)
}

func (Codec) ExtractConfig(plain []byte) ([]byte, error) {
	return backup.ExtractConfig(plain)
}

func (Codec) StableView(config []byte) []byte { return backup.StableConfig(config) }
