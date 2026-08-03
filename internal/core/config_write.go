package core

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Sentinel errors so callers (the HTTP layer) can map an edit failure to the
// right status without string-matching.
var (
	ErrDeviceExists = errors.New("device already exists")
	ErrNoSuchDevice = errors.New("no such device")
)

// selfsight can edit config.yaml on the user's behalf — add, remove, or update
// a device from the UI. The file stays the source of truth and stays
// hand-editable; these functions only ever change the one device entry
// involved, preserving the rest of the file (comments, key order, other
// devices) via YAML node surgery, and always write a timestamped backup of the
// previous file first so any edit is reversible.

var configWriteMu sync.Mutex // serialize read-modify-write of the config file

// AddDevice appends dev to the config file at path. Errors if a device with the
// same name already exists.
func AddDevice(path string, dev Device) (*Config, error) {
	return editConfigFile(path, func(devices *yaml.Node) error {
		if deviceIndex(devices, dev.Name) >= 0 {
			return fmt.Errorf("%w: %q", ErrDeviceExists, dev.Name)
		}
		n, err := encodeDevice(dev)
		if err != nil {
			return err
		}
		devices.Content = append(devices.Content, n)
		return nil
	})
}

// RemoveDevice deletes the named device from the config file. Backups already
// on disk under the data dir are left untouched.
func RemoveDevice(path, name string) (*Config, error) {
	return editConfigFile(path, func(devices *yaml.Node) error {
		idx := deviceIndex(devices, name)
		if idx < 0 {
			return fmt.Errorf("%w: %q", ErrNoSuchDevice, name)
		}
		devices.Content = append(devices.Content[:idx], devices.Content[idx+1:]...)
		return nil
	})
}

// UpdateDevice replaces the entry currently named name with dev (dev.Name may
// differ, i.e. a rename). Only that one entry is rewritten.
//
// A blank Password or Serial means "keep the current one". The kept value is
// taken from the RAW file node — never from the loaded (env-expanded) config —
// so a `password: ${VAR}` reference survives verbatim instead of being
// materialized into the file as the expanded secret.
func UpdateDevice(path, name string, dev Device) (*Config, error) {
	return editConfigFile(path, func(devices *yaml.Node) error {
		idx := deviceIndex(devices, name)
		if idx < 0 {
			return fmt.Errorf("%w: %q", ErrNoSuchDevice, name)
		}
		if dev.Name != name && deviceIndex(devices, dev.Name) >= 0 {
			return fmt.Errorf("%w: %q", ErrDeviceExists, dev.Name)
		}
		if dev.Password == "" {
			if v := mappingValue(devices.Content[idx], "password"); v != nil {
				dev.Password = v.Value
			}
		}
		if dev.Serial == "" {
			if v := mappingValue(devices.Content[idx], "serial"); v != nil {
				dev.Serial = v.Value
			}
		}
		preserveSSIDPassphrases(devices.Content[idx], &dev)
		n, err := encodeDevice(dev)
		if err != nil {
			return err
		}
		devices.Content[idx] = n
		return nil
	})
}

// preserveSSIDPassphrases carries each declared SSID's stored passphrase
// forward when the incoming entry leaves it blank. Blank means "unchanged",
// the same rule as the device password and for the same reason: the dashboard
// is never sent the current passphrase, so it cannot send one back. Read from
// the RAW file node, so a `${VAR}` reference survives as a reference rather
// than being written out as the expanded secret.
func preserveSSIDPassphrases(entry *yaml.Node, dev *Device) {
	desired := mappingValue(entry, "desired")
	if desired == nil {
		return
	}
	ssids := mappingValue(desired, "ssids")
	if ssids == nil || ssids.Kind != yaml.SequenceNode {
		return
	}
	stored := map[string]string{}
	for _, node := range ssids.Content {
		if node.Kind != yaml.MappingNode {
			continue
		}
		name, pass := mappingValue(node, "name"), mappingValue(node, "passphrase")
		if name != nil && pass != nil {
			stored[name.Value] = pass.Value
		}
	}
	for i := range dev.Desired.SSIDs {
		if dev.Desired.SSIDs[i].Passphrase == "" {
			dev.Desired.SSIDs[i].Passphrase = stored[dev.Desired.SSIDs[i].Name]
		}
	}
}

// editConfigFile parses the config document, hands the `devices` sequence node
// to mutate, then validates the result and writes it back atomically (after
// backing up the previous file). A mutation that produces an invalid config is
// rejected and the file is left untouched.
func editConfigFile(path string, mutate func(devices *yaml.Node) error) (*Config, error) {
	configWriteMu.Lock()
	defer configWriteMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	root := documentRoot(&doc)
	if root == nil {
		return nil, fmt.Errorf("config: unexpected top-level structure")
	}
	devices := mappingValue(root, "devices")
	if devices == nil {
		devices = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "devices"}, devices)
	}
	if devices.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("config: devices is not a list")
	}

	if err := mutate(devices); err != nil {
		return nil, err
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, err
	}
	// Validate the raw text (a ${VAR} reference is a valid non-empty value here;
	// we're only checking structure, not resolving secrets).
	if _, err := parseConfig(out); err != nil {
		return nil, fmt.Errorf("resulting config is invalid, no change written: %w", err)
	}
	if err := backupAndWrite(path, data, out); err != nil {
		return nil, err
	}
	// Return the fully loaded config (env-expanded) so callers that swap it into
	// a running server get real secrets, not literal ${VAR} for untouched devices.
	return LoadConfig(path)
}

// encodeDevice turns a Device into a YAML mapping node (respecting omitempty,
// so a device with no desired config doesn't emit an empty `desired:` block).
func encodeDevice(dev Device) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(dev); err != nil {
		return nil, err
	}
	return &n, nil
}

func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 { // empty file — start a fresh mapping document
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode {
		return doc.Content[0]
	}
	return nil
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func deviceIndex(devices *yaml.Node, name string) int {
	for i, entry := range devices.Content {
		if entry.Kind != yaml.MappingNode {
			continue
		}
		if v := mappingValue(entry, "name"); v != nil && v.Value == name {
			return i
		}
	}
	return -1
}

func backupAndWrite(path string, prev, next []byte) error {
	bak := fmt.Sprintf("%s.bak-%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(bak, prev, 0o600); err != nil {
		return fmt.Errorf("back up config before writing: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, next, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
