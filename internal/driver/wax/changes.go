package wax

import (
	"context"
	"fmt"
	"strings"
	"time"

	"selfsight/internal/core"
	"selfsight/internal/device"
)

// After a channel write bounces the radio, the radio takes a few seconds to
// re-tune before it reports the new operating channel. Verify polls the
// operating channel this long before giving up (vars, not consts, so tests can
// shorten them).
var (
	channelSettle = 60 * time.Second
	channelPoll   = 5 * time.Second
)

// This file implements the typed write surface of device.Driver: each method
// wraps a protocol-level Change (read-modify-write of the AP's full blocks,
// verified by read-back) in the guarded Apply pipeline. The server never sees
// wlan keys, vap slots, or write payloads — that vocabulary stays here.

// Compile-time proof that the wax driver satisfies the vendor contract.
var _ device.Driver = (*Manager)(nil)

// keyToWlan maps the config's radio keys to the AP's internal band keys.
var keyToWlan = map[string]string{"2g": "wlan0", "5g": "wlan1", "6g": "wlan2"}

// widthCode maps a channel width in MHz (the config vocabulary) to the AP's
// numeric channelWidth code, and widthLabel to the label its live status
// reports. Codes were captured live from a WAX610 (2.4 GHz): "0"=20 MHz,
// "1"=40 MHz, "2"/"3"=20/40 MHz (the radios ship on "3"). Only the widths
// selfsight actually writes are mapped. Every width write is still read-back
// verified against the operating label, so a wrong code is caught and the
// pre-write backup makes it reversible.
var widthCode = map[string]string{"20": "0", "40": "1"}

// widthLabel is the operating-width string the live monitor reports for a
// width. Narrowing to 20 MHz reports the unambiguous "20 MHz" (no "/"), which
// is what the verify below confirms.
var widthLabel = map[string]string{"20": "20 MHz", "40": "40 MHz"}

// ApplySSID updates the named network to the declared shape, creating it in a
// free slot if the device doesn't have it.
func (m *Manager) ApplySSID(ctx context.Context, backupDir string, want core.SSID) (*ApplyResult, error) {
	return m.Apply(ctx, backupDir, ssidChange(want))
}

// DeleteSSID removes a network from the device (the primary slot is refused).
func (m *Manager) DeleteSSID(ctx context.Context, backupDir, name string) (*ApplyResult, error) {
	return m.Apply(ctx, backupDir, deleteSSIDChange(name))
}

// ApplyRadios sets channels and/or on-off per band ("2g"/"5g"/"6g" keys) in
// one combined write — every radio write bounces the radios, so once is enough.
func (m *Manager) ApplyRadios(ctx context.Context, backupDir string, bands map[string]core.Radio) (*ApplyResult, error) {
	channels, widths, status := map[string]string{}, map[string]string{}, map[string]string{}
	for key, r := range bands {
		wl := keyToWlan[key]
		if wl == "" {
			return nil, fmt.Errorf("wax: unknown radio band %q (use 2g, 5g, or 6g)", key)
		}
		if r.Channel != "" {
			channels[wl] = r.Channel
		}
		if r.Width != "" {
			if _, ok := widthCode[r.Width]; !ok {
				return nil, fmt.Errorf("wax: unsupported channel width %q (use 20, 40, or 80)", r.Width)
			}
			widths[wl] = r.Width
		}
		if r.Enabled != nil {
			status[wl] = map[bool]string{true: "1", false: "0"}[*r.Enabled]
		}
	}
	if len(channels) == 0 && len(widths) == 0 && len(status) == 0 {
		return nil, fmt.Errorf("wax: radio change carries nothing to write")
	}
	return m.Apply(ctx, backupDir, radioCoreChange(channels, widths, status))
}

// SetName sets the device's admin-visible name.
func (m *Manager) SetName(ctx context.Context, backupDir, name string) (*ApplyResult, error) {
	return m.Apply(ctx, backupDir, APNameChange(name))
}

// MatchPassphrase reports whether the device's key for the named network is
// the passphrase given. The AP's status read does not carry keys; the slot
// table does, so this reads that and compares inside the driver — the answer
// crosses the boundary, the key never does.
func (m *Manager) MatchPassphrase(ctx context.Context, name, passphrase string) (bool, error) {
	if !m.hasSession {
		if err := m.login(ctx); err != nil {
			return false, err
		}
	}
	ok, err := verifyPassphrase(ctx, m.client, name, passphrase)
	if err != nil && m.recoverable(err) {
		if lerr := m.login(ctx); lerr != nil {
			return false, lerr
		}
		ok, err = verifyPassphrase(ctx, m.client, name, passphrase)
	}
	if err != nil {
		return false, err
	}
	_ = m.saveSession()
	return ok, nil
}

// ValidateSecurity reports whether the config security label is one this
// device supports. Pure — no network.
func (m *Manager) ValidateSecurity(label string) error {
	_, _, err := SecurityCodes(label)
	return err
}

// deleteSSIDChange resolves an SSID name to its slot and deletes that slot.
func deleteSSIDChange(name string) Change {
	return Change{
		Describe: "delete ssid " + name,
		Write: func(ctx context.Context, c *Client) error {
			slots, err := c.SSIDSlots(ctx)
			if err != nil {
				return err
			}
			var found []string
			for _, slot := range sortedKeys(slots) {
				for _, sv := range slots[slot] {
					if sv.Core.SSID == name {
						found = append(found, slot)
						break
					}
				}
			}
			switch {
			case len(found) == 0:
				return fmt.Errorf("no ssid %q on the device", name)
			case len(found) > 1:
				return fmt.Errorf("ssid %q exists in multiple slots (%s) — ambiguous, refusing to guess", name, strings.Join(found, ", "))
			}
			return c.DeleteSSIDSlot(ctx, found[0]) // refuses SSID1 itself
		},
		Verify: func(ctx context.Context, c *Client) (bool, string, error) {
			ssids, err := c.SSIDs(ctx)
			if err != nil {
				return false, "", err
			}
			for _, s := range ssids {
				if s.Name == name {
					return false, "ssid " + name + " still present", nil
				}
			}
			return true, "ssid " + name + " removed", nil
		},
	}
}

// ssidChange updates an existing SSID's declared fields, or creates the SSID
// in a free slot if the device doesn't have it. Both are read-modify-writes of
// the full core block (partial writes are rejected by the AP).
func ssidChange(want core.SSID) Change {
	return Change{
		Describe: "apply ssid " + want.Name,
		Write: func(ctx context.Context, c *Client) error {
			slots, err := c.SSIDSlots(ctx)
			if err != nil {
				return err
			}
			for slot, bands := range slots {
				for _, band := range sortedKeys(bands) {
					sv := bands[band]
					if sv.Core.SSID != want.Name {
						continue
					}
					core, err := desiredCore(sv.Core, want)
					if err != nil {
						return err
					}
					if err := c.WriteSSID(ctx, slot, band, sv.Vap, core); err != nil {
						return err
					}
				}
			}
			for _, bands := range slots {
				for _, sv := range bands {
					if sv.Core.SSID == want.Name {
						return nil // updated in place above
					}
				}
			}
			return createSSID(ctx, c, want)
		},
		Verify: func(ctx context.Context, c *Client) (bool, string, error) {
			ssids, err := c.SSIDs(ctx)
			if err != nil {
				return false, "", err
			}
			for _, s := range ssids {
				if s.Name != want.Name {
					continue
				}
				ok := (want.VLAN == 0 || s.VLAN == want.VLAN) &&
					(want.Security == "" || normEq(want.Security, s.Security)) &&
					(want.Hidden == nil || s.Hidden == *want.Hidden) &&
					(want.Enabled == nil || s.Enabled == *want.Enabled)
				obs := fmt.Sprintf("ssid %s vlan=%d security=%s hidden=%t enabled=%t",
					s.Name, s.VLAN, s.Security, s.Hidden, s.Enabled)
				if want.Passphrase != "" {
					// The deduplicated SSID view omits the key; the slot table
					// carries it, so compare there — but never echo the value.
					pok, err := verifyPassphrase(ctx, c, want.Name, want.Passphrase)
					if err != nil {
						return false, "", err
					}
					ok = ok && pok
					obs += fmt.Sprintf(" passphrase-confirmed=%t", pok)
				}
				return ok, obs, nil
			}
			return false, "ssid " + want.Name + " missing", nil
		},
	}
}

// verifyPassphrase reads the slot table (the only read that carries the key)
// and reports whether every band carrying the SSID now has the wanted key.
func verifyPassphrase(ctx context.Context, c *Client, name, key string) (bool, error) {
	slots, err := c.SSIDSlots(ctx)
	if err != nil {
		return false, err
	}
	found := false
	for _, bands := range slots {
		for _, sv := range bands {
			if sv.Core.SSID != name {
				continue
			}
			found = true
			if sv.Core.PresharedKey != key {
				return false, nil
			}
		}
	}
	return found, nil
}

// createSSID writes a declared SSID into the device's next free slot.
func createSSID(ctx context.Context, c *Client, want core.SSID) error {
	auth, enc, err := SecurityCodes(securityOrDefault(want.Security))
	if err != nil {
		return err
	}
	if auth != 0 && want.Passphrase == "" {
		return fmt.Errorf("cannot create ssid %q: a new %s network needs a passphrase", want.Name, securityOrDefault(want.Security))
	}
	slot, vaps, err := c.SSIDFree(ctx)
	if err != nil {
		return err
	}
	vlan := want.VLAN
	if vlan == 0 {
		vlan = 1
	}
	// A new SSID defaults to enabled and broadcast unless declared otherwise.
	enabled, hidden := 1, 0
	if want.Enabled != nil {
		enabled = boolTo01(*want.Enabled)
	}
	if want.Hidden != nil {
		hidden = boolTo01(*want.Hidden)
	}
	core := SSIDCore{
		VapProfileStatus: enabled, SSID: want.Name, HideNetworkName: hidden,
		AuthType: auth, Encryption: enc, PresharedKey: want.Passphrase, VlanID: vlan,
	}
	for _, band := range sortedKeys(vaps) {
		if err := c.WriteSSID(ctx, slot, band, vaps[band], core); err != nil {
			return err
		}
	}
	return nil
}

// desiredCore overlays the declared fields onto a band's current core block.
// Undeclared fields keep their current device values — declared config only
// manages what the user wrote down.
func desiredCore(cur SSIDCore, want core.SSID) (SSIDCore, error) {
	out := cur
	if want.VLAN != 0 {
		out.VlanID = want.VLAN
	}
	if want.Security != "" {
		auth, enc, err := SecurityCodes(want.Security)
		if err != nil {
			return out, err
		}
		out.AuthType, out.Encryption = auth, enc
	}
	if want.Passphrase != "" {
		// A key on an open network is dead weight the AP may reject or ignore;
		// the network must get a security mode (here or already on the device)
		// for the passphrase to mean anything.
		if out.AuthType == 0 {
			return out, fmt.Errorf("ssid %q is open (no password) — set a security mode before setting a passphrase", want.Name)
		}
		out.PresharedKey = want.Passphrase
	}
	if want.Hidden != nil {
		out.HideNetworkName = boolTo01(*want.Hidden)
	}
	if want.Enabled != nil {
		out.VapProfileStatus = boolTo01(*want.Enabled)
	}
	return out, nil
}

func boolTo01(b bool) int {
	if b {
		return 1
	}
	return 0
}

// radioCoreChange sets channels, channel widths, and/or radio on-off on the
// given bands in one combined write carrying every band's full current core
// block (the proven-safe shape). Turning a radio off drops its clients until
// turned back on — by device design; the confirmation UI is the consent step.
func radioCoreChange(channels, widths, status map[string]string) Change {
	var desc []string
	for _, wl := range sortedKeys(channels) {
		desc = append(desc, wl+"→ch "+channels[wl])
	}
	for _, wl := range sortedKeys(widths) {
		desc = append(desc, wl+"→"+widths[wl]+" MHz")
	}
	for _, wl := range sortedKeys(status) {
		desc = append(desc, wl+"→"+map[string]string{"1": "on", "0": "off"}[status[wl]])
	}
	return Change{
		Describe: "apply radio settings (" + strings.Join(desc, ", ") + ")",
		Write: func(ctx context.Context, c *Client) error {
			cores, err := c.RadioCores(ctx)
			if err != nil {
				return err
			}
			for wl, ch := range channels {
				core, ok := cores[wl]
				if !ok {
					return fmt.Errorf("device has no %s radio", wl)
				}
				core.Channel = ch
				cores[wl] = core
			}
			for wl, mhz := range widths {
				core, ok := cores[wl]
				if !ok {
					return fmt.Errorf("device has no %s radio", wl)
				}
				core.ChannelWidth = widthCode[mhz]
				cores[wl] = core
			}
			for wl, st := range status {
				core, ok := cores[wl]
				if !ok {
					return fmt.Errorf("device has no %s radio", wl)
				}
				core.RadioStatus = st
				cores[wl] = core
			}
			return c.WriteRadios(ctx, cores)
		},
		Verify: func(ctx context.Context, c *Client) (bool, string, error) {
			ok := true
			var obs []string

			// Channels and widths both show up in the live monitor, and both
			// re-tune a few seconds after the write bounces the radio — so
			// confirm them together against what the radio is actually OPERATING
			// on (not merely what the config stored). A device can accept a value
			// into config yet keep the radio as it was (e.g. a channel it cannot
			// run at the current width), so verifying the config alone reports a
			// false success. Poll until both settle or the budget runs out.
			// "auto" channel means "device's choice", so any channel counts.
			if len(channels) > 0 || len(widths) > 0 {
				deadline := time.Now().Add(channelSettle)
				for {
					curCh, err := c.operatingChannels(ctx)
					if err != nil {
						return false, "", err
					}
					curW, err := c.operatingWidths(ctx)
					if err != nil {
						return false, "", err
					}
					ok = true
					obs = nil
					for _, wl := range sortedKeys(channels) {
						got := curCh[wl]
						if channels[wl] != "auto" && got != channels[wl] {
							ok = false
						}
						obs = append(obs, wl+"=ch "+got)
					}
					for _, wl := range sortedKeys(widths) {
						got := curW[wl]
						if got != widthLabel[widths[wl]] {
							ok = false
						}
						obs = append(obs, wl+"="+got)
					}
					if ok || time.Now().After(deadline) {
						break
					}
					select {
					case <-ctx.Done():
						return false, "", ctx.Err()
					case <-time.After(channelPoll):
					}
				}
			}

			// Radio on/off is a config-level setting; confirm it from the
			// writable block.
			if len(status) > 0 {
				cores, err := c.RadioCores(ctx)
				if err != nil {
					return false, "", err
				}
				for _, wl := range sortedKeys(status) {
					got := cores[wl].RadioStatus
					if got != status[wl] {
						ok = false
					}
					obs = append(obs, wl+"="+map[string]string{"1": "on", "0": "off"}[got])
				}
			}

			return ok, strings.Join(obs, ", "), nil
		},
	}
}

// operatingChannels reads the live monitor state and returns, per wlan key, the
// channel each radio is currently ON — the channel the dashboard and users see,
// which can differ from the configured channel when the device won't run the
// configured one.
func (c *Client) operatingChannels(ctx context.Context) (map[string]string, error) {
	si, err := c.SystemInfo(ctx)
	if err != nil {
		return nil, err
	}
	labelToWlan := map[string]string{}
	for wl, label := range bandLabel {
		labelToWlan[label] = wl
	}
	out := map[string]string{}
	for _, r := range si.Radios {
		if wl := labelToWlan[r.Band]; wl != "" {
			out[wl] = r.Channel
		}
	}
	return out, nil
}

// operatingWidths reads the live monitor state and returns, per wlan key, the
// channel-width label each radio is currently running (e.g. "20 MHz",
// "20/40 MHz"). Like the operating channel, this is what the radio actually
// does, which can differ from the configured width code.
func (c *Client) operatingWidths(ctx context.Context) (map[string]string, error) {
	si, err := c.SystemInfo(ctx)
	if err != nil {
		return nil, err
	}
	labelToWlan := map[string]string{}
	for wl, label := range bandLabel {
		labelToWlan[label] = wl
	}
	out := map[string]string{}
	for _, r := range si.Radios {
		if wl := labelToWlan[r.Band]; wl != "" {
			out[wl] = r.ChannelWidth
		}
	}
	return out, nil
}

func securityOrDefault(s string) string {
	if s == "" {
		return "wpa2-psk"
	}
	return s
}

func normEq(a, b string) bool { return core.NormSecurity(a) == core.NormSecurity(b) }
