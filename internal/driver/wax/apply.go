package wax

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Reads that exist for the sake of writes: every wireless write is a
// read-modify-write of a full core block (oracle-confirmed shapes; sending a
// partial block or the full read response is rejected with status 1).
const (
	payloadSSIDFree  = `{"system":{"wlanSettings":{"wlanSettingTable":{"ssidGetFree":""}}}}`
	payloadRadioCore = `{"system":{"wlanSettings":{"wlanSettingTable":{"wlan0":{"radioStatus":"","operateMode":"","guardInterval":"","txPower":"","channel":"","channelWidth":"","beamForming":""},"wlan1":{"radioStatus":"","operateMode":"","guardInterval":"","txPower":"","channel":"","channelWidth":"","beamForming":""}}}}}`
)

// SlotVap is one SSID slot's presence on one band: the vap key writes must
// target and the current core block to carry forward.
type SlotVap struct {
	Vap  string
	Core SSIDCore
}

// SSIDSlots reads the full wireless config and returns slot → band → vap+core,
// the raw material for SSID read-modify-writes (unlike SSIDs, which is the
// deduplicated read-only view).
func (c *Client) SSIDSlots(ctx context.Context) (map[string]map[string]SlotVap, error) {
	var r struct {
		System struct {
			WlanSettings struct {
				Table struct {
					Details map[string]json.RawMessage `json:"ssidGetDetails"`
				} `json:"wlanSettingTable"`
			} `json:"wlanSettings"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadSSIDDetails, &r); err != nil {
		return nil, err
	}
	out := map[string]map[string]SlotVap{}
	for slot, raw := range r.System.WlanSettings.Table.Details {
		var bands map[string]json.RawMessage
		if err := json.Unmarshal(raw, &bands); err != nil {
			continue
		}
		for bandKey, braw := range bands {
			if !strings.HasPrefix(bandKey, "wlan") {
				continue
			}
			var vaps map[string]json.RawMessage
			if err := json.Unmarshal(braw, &vaps); err != nil {
				continue
			}
			for vapKey, vraw := range vaps {
				var core SSIDCore
				if err := json.Unmarshal(vraw, &core); err != nil || core.SSID == "" {
					continue
				}
				if out[slot] == nil {
					out[slot] = map[string]SlotVap{}
				}
				out[slot][bandKey] = SlotVap{Vap: vapKey, Core: core}
			}
		}
	}
	return out, nil
}

// SSIDFree reads the next free SSID slot and its per-band vap keys. A band
// whose vap is "none" cannot host the new SSID and is skipped by callers.
func (c *Client) SSIDFree(ctx context.Context) (slot string, vaps map[string]string, err error) {
	var r struct {
		System struct {
			WlanSettings struct {
				Table struct {
					Free map[string]json.RawMessage `json:"ssidGetFree"`
				} `json:"wlanSettingTable"`
			} `json:"wlanSettings"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadSSIDFree, &r); err != nil {
		return "", nil, err
	}
	for _, key := range sortedKeys(r.System.WlanSettings.Table.Free) {
		if key == "available" {
			continue
		}
		var perBand map[string]string
		if err := json.Unmarshal(r.System.WlanSettings.Table.Free[key], &perBand); err != nil {
			continue
		}
		clean := map[string]string{}
		for band, vap := range perBand {
			if strings.HasPrefix(band, "wlan") && vap != "" && vap != "none" {
				clean[band] = vap
			}
		}
		if len(clean) > 0 {
			return key, clean, nil
		}
	}
	return "", nil, fmt.Errorf("wax: no free SSID slot on the device")
}

// RadioCores reads both bands' full writable radio block. Radio writes must
// carry the untouched band's complete current state (the proven-safe shape),
// so this is always the first step of a radio change.
func (c *Client) RadioCores(ctx context.Context) (map[string]RadioWrite, error) {
	var r struct {
		System struct {
			WlanSettings struct {
				Table map[string]RadioWrite `json:"wlanSettingTable"`
			} `json:"wlanSettings"`
		} `json:"system"`
	}
	if err := c.socket(ctx, payloadRadioCore, &r); err != nil {
		return nil, err
	}
	out := map[string]RadioWrite{}
	for band, rw := range r.System.WlanSettings.Table {
		if strings.HasPrefix(band, "wlan") {
			out[band] = rw
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wax: radio core read returned no bands")
	}
	return out, nil
}

// SecurityCodes maps a normalized security label to the AP's numeric
// authenticationType/encryption pair (the inverse of securityLabel).
func SecurityCodes(label string) (auth, enc int, err error) {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "OPEN":
		return 0, 0, nil
	case "WPA2-PSK":
		return 32, 4, nil
	case "WPA3-SAE":
		return 64, 4, nil
	case "WPA2/WPA3":
		return 96, 4, nil
	default:
		return 0, 0, fmt.Errorf("wax: unsupported security %q (use open, wpa2-psk, wpa3-sae, or wpa2/wpa3)", label)
	}
}
