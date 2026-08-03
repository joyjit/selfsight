package wax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// writeSocket posts a write payload to /socketCommunication. Wireless writes
// bounce the radio, so the AP often drops the response (a transport error/empty
// body) even when the write took effect — the driver never trusts the write
// response and always verifies by read-back (DESIGN.md, "Write responses lie").
//
// It returns an error only for a *definitive* rejection (bad keys, auth dead,
// managed lock, or an explicit non-zero API status). A transport/ambiguous
// outcome returns nil and leaves the verdict to the caller's read-back.
func (c *Client) writeSocket(ctx context.Context, payload string) error {
	err := c.socket(ctx, payload, nil)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrBadRequest), errors.Is(err, ErrManaged), errors.Is(err, ErrAuthExpired):
		return err
	default:
		var ae *APIError
		if errors.As(err, &ae) {
			return err
		}
		return nil // transport / empty body from a radio bounce — verify decides
	}
}

// SetAPName writes the device name. This is a simple basicSettings leaf (no
// radio bounce) and is the reference write proven against live hardware.
func (c *Client) SetAPName(ctx context.Context, name string) error {
	return c.writeSocket(ctx, mustJSON(map[string]any{
		"system": map[string]any{"basicSettings": map[string]any{"apName": name}},
	}))
}

// SSIDCore is the minimal writable SSID block. Writes go through the separate
// write key `ssidSetDetails` (the read key `ssidGetDetails` is read-only), and
// must carry exactly this core set — read-modify-write the whole block even to
// change one field (DESIGN.md / oracle notes).
type SSIDCore struct {
	VapProfileStatus int    `json:"vapProfileStatus"`
	SSID             string `json:"ssid"`
	HideNetworkName  int    `json:"hideNetworkName"`
	AuthType         int    `json:"authenticationType"`
	Encryption       int    `json:"encryption"`
	PresharedKey     string `json:"presharedKey"`
	VlanID           int    `json:"vlanID"`
}

// WriteSSID writes one SSID's core block into the given slot/band/vap (e.g.
// "SSID1","wlan0","vap0"). Wireless write — verify by read-back afterwards.
func (c *Client) WriteSSID(ctx context.Context, slot, band, vap string, core SSIDCore) error {
	return c.writeSocket(ctx, mustJSON(map[string]any{
		"system": map[string]any{
			"wlanSettings": map[string]any{
				"wlanSettingTable": map[string]any{
					"ssidSetDetails": map[string]any{
						slot: map[string]any{band: map[string]any{vap: core}},
					},
				},
			},
		},
	}))
}

// DeleteSSIDSlot removes an SSID slot from the device (e.g. "SSID2"). The
// write key is `ssidDelete` with the slot name and an empty value — the
// oracle-proven shape (live-confirmed 2026-07-10: slot returned to ssidGetFree,
// zero drift vs baseline). Wireless write — bounces the radio; verify by
// reading the slot table back. SSID1 is refused here, at the lowest level:
// that slot is the device's primary network and deleting it is not a
// supported operation.
func (c *Client) DeleteSSIDSlot(ctx context.Context, slot string) error {
	if slot == "SSID1" {
		return fmt.Errorf("wax: refusing to delete SSID1 — the device's primary network")
	}
	return c.writeSocket(ctx, mustJSON(map[string]any{
		"system": map[string]any{
			"wlanSettings": map[string]any{
				"wlanSettingTable": map[string]any{
					"ssidDelete": map[string]any{slot: ""},
				},
			},
		},
	}))
}

// RadioWrite is one band's writable radio state. The write key is the same as
// the read key (`wlanSettingTable`, unlike SSID). The proven-safe shape sends
// the changed band's fields plus the *other* band's full current snapshot, so
// callers pass both bands (read-modify-write).
type RadioWrite struct {
	RadioStatus   string `json:"radioStatus,omitempty"`
	OperateMode   string `json:"operateMode,omitempty"`
	Channel       string `json:"channel,omitempty"`
	ChannelWidth  string `json:"channelWidth,omitempty"`
	TxPower       string `json:"txPower,omitempty"`
	GuardInterval string `json:"guardInterval,omitempty"`
	BeamForming   string `json:"beamForming,omitempty"`
}

// WriteRadios writes per-band radio settings (keys "wlan0"/"wlan1"). Wireless
// write — bounces the radios; verify by read-back.
func (c *Client) WriteRadios(ctx context.Context, bands map[string]RadioWrite) error {
	table := make(map[string]any, len(bands))
	for band, rw := range bands {
		table[band] = rw
	}
	return c.writeSocket(ctx, mustJSON(map[string]any{
		"system": map[string]any{
			"wlanSettings": map[string]any{"wlanSettingTable": table},
		},
	}))
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("wax: marshal write payload: %v", err)) // only static maps reach here
	}
	return string(b)
}
