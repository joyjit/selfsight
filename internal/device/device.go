// Package device is the vendor boundary: everything the selfsight server
// knows about an access point goes through the Driver and Codec contracts
// defined here, and every vendor-specific detail — protocol, sessions,
// archive format, crypto — lives behind them in a driver package
// (internal/driver/wax is the first). Supporting another brand means
// implementing these two interfaces and wiring the model into the server's
// driver factory; no server code should need to change.
package device

import (
	"context"
	"errors"
	"time"

	"selfsight/internal/core"
)

// ErrManaged reports that the device refused local management because a
// vendor cloud controller owns it. Drivers wrap this sentinel so the server
// can classify the condition with errors.Is without knowing the vendor.
var ErrManaged = errors.New("device is cloud-managed — local API locked")

// Driver is one access point, session lifecycle included. Implementations
// are not safe for concurrent use — the server serializes calls per device,
// and fleet-wide writes are strictly sequential by policy.
//
// Every write method is a guarded write: the driver takes a fresh backup
// into backupDir first, then writes, then confirms the result by reading the
// device back — a write response alone is never trusted.
type Driver interface {
	// Status reads the device's full live state.
	Status(ctx context.Context) (*Status, error)

	// ApplySSID updates the named wireless network to the declared shape, or
	// creates it if the device doesn't have it.
	ApplySSID(ctx context.Context, backupDir string, want core.SSID) (*ApplyResult, error)
	// DeleteSSID removes a wireless network from the device.
	DeleteSSID(ctx context.Context, backupDir, name string) (*ApplyResult, error)
	// ApplyRadios updates per-band radio settings, keyed by the config's
	// band names ("2g", "5g", "6g"). One call, one radio bounce.
	ApplyRadios(ctx context.Context, backupDir string, bands map[string]core.Radio) (*ApplyResult, error)
	// SetName sets the device's admin-visible name.
	SetName(ctx context.Context, backupDir, name string) (*ApplyResult, error)

	// Backup downloads the device's config archive into dir (read-only on
	// the device) and returns the file path.
	Backup(ctx context.Context, dir string) (string, error)
	// Restore uploads an archive (already in the device's expected on-wire
	// form — see Codec.Encrypt) and confirms the outcome, waiting up to wait
	// for the device to settle.
	Restore(ctx context.Context, filename string, archive []byte, wait time.Duration) (*RestoreResult, error)

	// CheckFirmware asks the device to check for updates and reports state.
	CheckFirmware(ctx context.Context) (*Firmware, error)
	// Upgrade flashes the available firmware, reporting progress. The most
	// disruptive operation there is: reboots the device, drops every client.
	Upgrade(ctx context.Context, backupDir string, onProgress func(UpgradeProgress)) (*UpgradeOutcome, error)

	// ValidateSecurity reports whether the device supports a config security
	// label ("wpa2-psk", …). Pure — no network.
	ValidateSecurity(label string) error
}

// Codec is vendor knowledge about backup archives that is useful without a
// live device: the on-disk/on-wire format and its crypto. Pure functions
// over bytes.
type Codec interface {
	// IsEncrypted reports whether data is still in the vendor's encrypted
	// on-wire form (as opposed to a decoded archive).
	IsEncrypted(data []byte) bool
	// Decrypt turns an encrypted archive into the decoded form, verifying it
	// round-trips (a wrong password fails, never corrupts).
	Decrypt(data []byte, password string) ([]byte, error)
	// Encrypt turns a decoded archive back into the on-wire form the device
	// accepts for restore.
	Encrypt(plain []byte, password string) ([]byte, error)
	// ValidateArchive reports whether a decoded archive is complete enough
	// that the device would accept restoring it.
	ValidateArchive(plain []byte) error
	// AdminCredential extracts a stable fingerprint of the admin login the
	// archive carries, for password-revert warnings on restore.
	AdminCredential(plain []byte) (string, error)
	// ExtractConfig flattens the archive's configuration into sorted
	// one-setting-per-line "key value" text — the input to config history.
	ExtractConfig(plain []byte) ([]byte, error)
	// StableView normalizes flattened config for change detection: values
	// that churn on their own (re-wrapped secrets, bookkeeping timestamps)
	// are blanked so they never count as changes.
	StableView(config []byte) []byte
}

// Status is a full read of a device's live state. System is always present;
// the rest are best-effort (absent if that sub-read failed).
type Status struct {
	System        *SystemInfo    `json:"system"`
	SSIDs         []SSID         `json:"ssids,omitempty"`
	Clients       *Clients       `json:"clients,omitempty"`
	ClientList    []ClientDetail `json:"clientList,omitempty"`
	RadioSettings []RadioSetting `json:"radioSettings,omitempty"`
	Firmware      *Firmware      `json:"firmware,omitempty"`
}

// SystemInfo is the device's identity and live per-radio state.
type SystemInfo struct {
	Name       string `json:"name"`
	Serial     string `json:"serial"`
	MAC        string `json:"mac"`
	Firmware   string `json:"firmware"`
	IP         string `json:"ip"`
	Gateway    string `json:"gateway"`
	GatewayUp  bool   `json:"gatewayUp"`
	Uptime     string `json:"uptime"`
	Standalone bool   `json:"standalone"` // false = a vendor cloud manages it
	Devices    int    `json:"devices"`
	// FQDN is the name the device has been told to answer to, empty when unset.
	// Devices that gate access on the Host header accept this name in addition
	// to their IP, so it is the friendlier address to open a browser at.
	FQDN   string      `json:"fqdn,omitempty"`
	Radios []RadioStat `json:"radios"`
}

// RadioStat is one band's live operating state.
type RadioStat struct {
	Band         string `json:"band"`
	Mode         string `json:"mode"`
	Channel      string `json:"channel"`
	ChannelWidth string `json:"channelWidth"`
	Stations     int    `json:"stations"`
	Traffic      string `json:"traffic"`
	ChannelUtil  string `json:"channelUtil"`
	// Airtime split: SelfUtil is our own networks' share, ObssUtil is
	// overlapping OTHER networks (neighbours) — the outside-interference signal.
	SelfUtil string `json:"selfUtil"`
	ObssUtil string `json:"obssUtil"`
}

// RadioSetting is one band's configured state (not live stats).
type RadioSetting struct {
	Band       string `json:"band"`
	On         bool   `json:"on"`
	MaxClients int    `json:"maxClients"`
}

// SSID is one configured wireless network (deduped across bands).
type SSID struct {
	Name     string   `json:"name"`
	VLAN     int      `json:"vlan"`
	Security string   `json:"security"`
	Hidden   bool     `json:"hidden"`
	Enabled  bool     `json:"enabled"`
	Bands    []string `json:"bands"`
}

// Clients is the connected-client summary: a device-wide total plus per-SSID
// counts by band.
type Clients struct {
	Total   int         `json:"total"`
	PerSSID []SSIDCount `json:"perSSID"`
}

// SSIDCount is one SSID's client count on one band.
type SSIDCount struct {
	SSID  string `json:"ssid"`
	Band  string `json:"band"`
	Count int    `json:"count"`
}

// ClientDetail is one connected station: who it is and where it's attached.
type ClientDetail struct {
	Hostname string `json:"hostname"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	SSID     string `json:"ssid"`
	Band     string `json:"band"`
	OS       string `json:"os"`
	Mode     string `json:"mode"`
	VLAN     int    `json:"vlan"`
}

// Firmware is the device's firmware/update state.
type Firmware struct {
	UpdateAvailable bool   `json:"updateAvailable"`
	AvailableImage  string `json:"availableImage"`
	LastChecked     string `json:"lastChecked"`
	ReleaseNotesURL string `json:"releaseNotesURL"`
}

// ApplyResult is the outcome of one guarded write.
type ApplyResult struct {
	Change   string `json:"change"`
	Backup   string `json:"backup"`   // path to the pre-write backup
	Applied  bool   `json:"applied"`  // true only if read-back confirmed it
	Observed string `json:"observed"` // what the device reported after the write
}

// RestoreResult is the outcome of a guarded restore.
type RestoreResult struct {
	File     string `json:"file"`
	Rebooted bool   `json:"rebooted"` // true only if the reboot was confirmed
}

// UpgradeProgress is a single poll of an in-flight firmware upgrade.
type UpgradeProgress struct {
	Phase   string // "download" | "flash"
	Percent int
	Done    bool
}

// UpgradeOutcome is the result of a completed firmware upgrade attempt.
type UpgradeOutcome struct {
	Backup     string `json:"backup"`
	OldVersion string `json:"oldVersion"`
	NewVersion string `json:"newVersion"`
	Confirmed  bool   `json:"confirmed"` // new version read back and differs
}
