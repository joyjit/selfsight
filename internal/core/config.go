package core

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole of selfsight's desired state: the server settings, the
// device inventory, and each device's declared configuration. It is loaded
// from one YAML file the user owns and edits by hand. selfsight can also edit
// it on the user's behalf (add/remove/update a device from the UI) via the
// node-surgery helpers in config_write.go, which preserve comments, key order,
// and every entry they don't touch.
//
// Only declared fields are managed. Anything omitted is simply not diffed or
// written, so users can adopt selfsight one field at a time.
type Config struct {
	Server  Server   `yaml:"server"`
	Devices []Device `yaml:"devices"`
}

// Server holds process-level settings.
type Server struct {
	Listen      string        `yaml:"listen"`
	Auth        *Auth         `yaml:"auth"`
	Backups     *BackupPolicy `yaml:"backups"` // deprecated; accepted and ignored
	BackupCheck *BackupCheck  `yaml:"backupCheck"`
}

// Auth protects the selfsight UI/API with a password. Omitted entirely means
// no auth (trusted-LAN deployment, the v1 default). Plaintext in the config is
// the same documented trade-off as the device credentials: the file lives on a
// server the user controls, chmod 600.
type Auth struct {
	Password string `yaml:"password"`
}

// BackupPolicy is retained only for backward compatibility. Scheduled backups
// were removed: selfsight now backs a device up when its config actually
// changes, not on a timer (see internal/api, RunBackupWatcher). Because the
// config loader is strict, an existing config with a `server.backups:` block
// would otherwise fail to load — so the field is still accepted here and simply
// ignored (with a startup notice). New configs should omit it.
type BackupPolicy struct {
	Every string `yaml:"every"`
	Keep  int    `yaml:"keep"`
}

// Backup-check cadence defaults, used when server.backupCheck (or a field of
// it) is omitted. The interval floor keeps a typo from turning every AP into a
// perpetual backup download.
const (
	DefaultBackupStartupDelay = 2 * time.Minute
	DefaultBackupInterval     = 6 * time.Hour
	MinBackupInterval         = time.Minute
)

// BackupCheck tunes how often selfsight checks each device for a config change
// and, when it finds one, stores a backup. This is a *check* cadence, not a
// backup schedule: an unchanged config is never stored, so a check that finds
// nothing costs a config read and nothing else. Omit the block (or any field)
// to use the defaults above. Values are Go durations and, like any config
// value, may be `${VAR}` references so they can be set from the environment.
type BackupCheck struct {
	StartupDelay string `yaml:"startupDelay"` // first check this long after startup
	Interval     string `yaml:"interval"`     // routine cadence between checks
}

// Durations parses the check timings, applying the defaults for a nil receiver
// or any empty field. Safe to call on a nil *BackupCheck (returns the
// defaults). A malformed value, or an interval below the floor, is an error.
func (b *BackupCheck) Durations() (startup, interval time.Duration, err error) {
	// Keep the defaults in place even on error, so a caller that ignores err
	// (the watcher) still gets safe values rather than a zero, busy-looping one.
	startup, interval = DefaultBackupStartupDelay, DefaultBackupInterval
	if b == nil {
		return startup, interval, nil
	}
	if b.StartupDelay != "" {
		d, e := time.ParseDuration(b.StartupDelay)
		switch {
		case e != nil:
			return startup, interval, fmt.Errorf("server.backupCheck.startupDelay: %w", e)
		case d < 0:
			return startup, interval, fmt.Errorf("server.backupCheck.startupDelay: must not be negative")
		default:
			startup = d
		}
	}
	if b.Interval != "" {
		d, e := time.ParseDuration(b.Interval)
		switch {
		case e != nil:
			return startup, interval, fmt.Errorf("server.backupCheck.interval: %w", e)
		case d < MinBackupInterval:
			return startup, interval, fmt.Errorf("server.backupCheck.interval: %s is below the %s minimum", b.Interval, MinBackupInterval)
		default:
			interval = d
		}
	}
	return startup, interval, nil
}

// Device is one access point: how to reach it, how to log in, and (optionally)
// what its configuration should be.
//
// Serial pins the entry to a physical unit: recorded when the device is
// adopted (the add form's connection test reads it), and checked against the
// live device before every write-class operation (apply/restore/upgrade), so a
// host that now points at different hardware — DHCP reshuffle, replaced unit —
// can't receive another AP's config. Empty means unpinned (no check).
type Device struct {
	Name     string  `yaml:"name"`
	Host     string  `yaml:"host"`
	Model    string  `yaml:"model,omitempty"`
	Serial   string  `yaml:"serial,omitempty"`
	Username string  `yaml:"username"`
	Password string  `yaml:"password,omitempty"`
	Desired  Desired `yaml:"desired,omitempty"`
}

// Desired is the declared configuration for a device. Zero-valued sections mean
// "not managed", not "set to empty".
type Desired struct {
	SSIDs  []SSID           `yaml:"ssids,omitempty"`
	Radios map[string]Radio `yaml:"radios,omitempty"`
}

// SSID is one declared wireless network. The *bool fields are tri-state:
// nil (omitted) = not managed, true/false = enforce that value — matching the
// "only declared fields are managed" rule for booleans, where a plain bool
// couldn't distinguish "unset" from "false".
type SSID struct {
	Name       string `yaml:"name"`
	VLAN       int    `yaml:"vlan,omitempty"`
	Security   string `yaml:"security,omitempty"`
	Passphrase string `yaml:"passphrase,omitempty"`
	Hidden     *bool  `yaml:"hidden,omitempty"`  // hide the SSID from broadcast
	Enabled    *bool  `yaml:"enabled,omitempty"` // the network is active (vapProfileStatus)
}

// Radio is the declared state of one radio band (e.g. "2g", "5g").
//
// Power is recorded but not yet drift-checked or applied: the device's txPower
// value codes are unmapped (protocol work pending), and selfsight never writes
// values whose semantics aren't proven.
type Radio struct {
	Channel string `yaml:"channel,omitempty"` // "auto" or a number, kept as a string so "auto" is valid
	Width   string `yaml:"width,omitempty"`   // channel width in MHz: "20"/"40"/"80"; "" = not managed
	Power   string `yaml:"power,omitempty"`
	Enabled *bool  `yaml:"enabled,omitempty"` // radio on/off; nil = not managed
}

// DefaultListen is used when server.listen is omitted.
const DefaultListen = ":8080"

// LoadConfig reads and validates the config file at path.
//
// Unknown fields are rejected (KnownFields) so a typo like "passwrod" fails
// loudly at startup instead of silently leaving a field unmanaged — the safe
// default for a tool that will later write to real hardware.
//
// ${VAR} references are expanded from the environment first, so secrets
// (device passwords, the UI auth password) can live in a .env / the process
// environment and be kept out of the config file itself. Expansion happens
// only on load, never on write: the write path (config_write.go) edits the raw
// file text, so a ${VAR} reference in an untouched device survives verbatim.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded, err := expandEnv(data)
	if err != nil {
		return nil, err
	}
	return parseConfig(expanded)
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces every ${VAR} that appears in a scalar *value* of the
// config with the environment value of VAR, erroring if any referenced
// variable is unset — an unset password should fail loudly at startup, not
// silently become empty and confuse a later login. Only the explicit ${VAR}
// form is expanded; a bare "$" (e.g. in a passphrase) is left untouched.
//
// Expansion walks the YAML node tree rather than the raw text so a ${VAR}
// mentioned in a comment — or on a commented-out line — is never expanded (a
// common footgun when a user comments out an optional `password: ${X}` line).
func expandEnv(data []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return data, nil // not valid YAML; let parseConfig report the real error
	}
	var missing []string
	expand := func(s string) string {
		return envRef.ReplaceAllStringFunc(s, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return v
		})
	}
	// walkValue expands scalars; walkNode descends, skipping mapping keys so a
	// key never gets expanded (only values do).
	var walkNode, walkValue func(n *yaml.Node)
	walkValue = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode {
			n.Value = expand(n.Value)
			return
		}
		walkNode(n)
	}
	walkNode = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walkValue(n.Content[i+1])
			}
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walkValue(c)
			}
		}
	}
	walkNode(&doc)
	if len(missing) > 0 {
		return nil, fmt.Errorf("config references unset environment variable(s): %s", strings.Join(dedupe(missing), ", "))
	}
	return yaml.Marshal(&doc)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func parseConfig(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = DefaultListen
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// DeviceNameMax bounds a device name so it always fits inside a filesystem
// path component with room for the suffixes selfsight appends (.json, .log,
// .cfg).
const DeviceNameMax = 64

// deviceNameRe admits one safe path element: it must start with a letter or
// digit (so "." and ".." cannot be spelled) and may then use dot, dash and
// underscore. No separators, no spaces, no control characters.
var deviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidateDeviceName enforces that a device name is a single, safe path
// element.
//
// A name is not just a label: it becomes a directory and file name under the
// data directory (backups, status cache, event log, config history) and a path
// segment in the REST API. Anything that could climb out of those directories
// or confuse a path has to be refused here, at the one boundary every name
// crosses — Load and every inventory edit both validate through this — rather
// than patched at each of the places that later build a path.
func ValidateDeviceName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("name is required")
	case len(name) > DeviceNameMax:
		return fmt.Errorf("name is too long (%d characters, max %d)", len(name), DeviceNameMax)
	case !deviceNameRe.MatchString(name):
		return fmt.Errorf("name %q is not usable as a file name: use letters, digits, dot, dash or underscore, starting with a letter or digit", name)
	}
	return nil
}

func (c *Config) validate() error {
	if a := c.Server.Auth; a != nil && a.Password == "" {
		return fmt.Errorf("server.auth: password is required when auth is enabled")
	}
	// server.backups is deprecated and ignored (see BackupPolicy); no validation.
	if _, _, err := c.Server.BackupCheck.Durations(); err != nil {
		return err
	}
	// An empty inventory is valid: selfsight can start with no devices and
	// adopt them from the UI (discover → Add), and removing the last device
	// must not be blocked. The dashboard shows an empty state in that case.
	seen := make(map[string]bool, len(c.Devices))
	for i, d := range c.Devices {
		where := fmt.Sprintf("devices[%d]", i)
		if d.Name != "" {
			where = fmt.Sprintf("device %q", d.Name)
		}
		if err := ValidateDeviceName(d.Name); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		switch {
		case d.Host == "":
			return fmt.Errorf("%s: host is required", where)
		case d.Username == "":
			return fmt.Errorf("%s: username is required", where)
		}
		if seen[d.Name] {
			return fmt.Errorf("duplicate device name %q", d.Name)
		}
		seen[d.Name] = true
	}
	return nil
}
