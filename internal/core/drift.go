package core

import (
	"strconv"
	"strings"
)

// DriftItem is one declared setting compared against what the device reports.
type DriftItem struct {
	Scope    string `json:"scope"` // e.g. "ssid:HomeNet" or "radio:5g"
	Field    string `json:"field"`
	Desired  string `json:"desired"`
	Observed string `json:"observed"`
	InSync   bool   `json:"inSync"`
}

// DriftReport is the full desired-vs-observed comparison for one device.
type DriftReport struct {
	InSync bool        `json:"inSync"`
	Items  []DriftItem `json:"items"`
}

// ObservedSSID and ObservedRadio are the device-reported values drift compares
// against. They are plain structs so this package stays independent of any
// device driver — the driver layer maps its reads into these.
type ObservedSSID struct {
	Name     string
	VLAN     int
	Security string // e.g. "WPA2-PSK/AES"
	Hidden   bool
	Enabled  bool
	// PassphraseMatch is whether the device's key for this network equals the
	// declared one. It is a pointer because the ordinary status read cannot
	// answer it — the driver has to be asked separately — so nil means "not
	// established", distinct from "does not match". The answer only ever
	// travels as this yes/no; the key itself never leaves the driver.
	PassphraseMatch *bool
}

// ObservedRadio is one band's observed state. Band uses the config's keys
// ("2g", "5g", "6g"). Enabled is a pointer because not every status read
// carries radioStatus — nil means "not observed", which never drifts.
type ObservedRadio struct {
	Band    string
	Channel string
	Enabled *bool
}

// ComputeDrift compares a device's desired config against observed values. Only
// declared fields are checked — anything the user didn't declare is not managed
// and never reported as drift (DESIGN.md, "Configuration model").
func ComputeDrift(d Desired, ssids []ObservedSSID, radios []ObservedRadio) DriftReport {
	obsSSID := make(map[string]ObservedSSID, len(ssids))
	for _, o := range ssids {
		obsSSID[o.Name] = o
	}
	obsRadio := make(map[string]ObservedRadio, len(radios))
	for _, o := range radios {
		obsRadio[o.Band] = o
	}

	var items []DriftItem
	add := func(scope, field, desired, observed string) {
		items = append(items, DriftItem{
			Scope: scope, Field: field, Desired: desired, Observed: observed,
			InSync: desired == observed,
		})
	}

	for _, want := range d.SSIDs {
		scope := "ssid:" + want.Name
		got, ok := obsSSID[want.Name]
		if !ok {
			items = append(items, DriftItem{
				Scope: scope, Field: "present", Desired: "yes", Observed: "missing", InSync: false,
			})
			continue
		}
		if want.VLAN != 0 {
			add(scope, "vlan", strconv.Itoa(want.VLAN), strconv.Itoa(got.VLAN))
		}
		if want.Security != "" {
			add(scope, "security", NormSecurity(want.Security), NormSecurity(got.Security))
		}
		if want.Hidden != nil {
			add(scope, "hidden", yesNo(*want.Hidden), yesNo(got.Hidden))
		}
		if want.Enabled != nil {
			add(scope, "enabled", yesNo(*want.Enabled), yesNo(got.Enabled))
		}
		if want.Passphrase != "" {
			// A declared passphrase drifts like anything else, but neither
			// side of the comparison may appear in the report — it is read by
			// whoever opens the dashboard. So the desired value is the fact
			// that one is declared, and the observed value is the verdict.
			// Anything short of a confirmed match counts as drift, including
			// "could not tell": erring the other way would quietly stop
			// reporting a wrong key the moment a read failed.
			observed := "unknown"
			if got.PassphraseMatch != nil {
				observed = "mismatch"
				if *got.PassphraseMatch {
					observed = "matches"
				}
			}
			items = append(items, DriftItem{
				Scope: scope, Field: "passphrase", Desired: "set", Observed: observed,
				InSync: got.PassphraseMatch != nil && *got.PassphraseMatch,
			})
		}
	}

	for band, want := range d.Radios {
		got, ok := obsRadio[band]
		if !ok {
			continue
		}
		// "auto" (or unset) channel means "don't manage the exact channel".
		if want.Channel != "" && !strings.EqualFold(want.Channel, "auto") {
			add("radio:"+band, "channel", want.Channel, got.Channel)
		}
		// Radio on/off drifts only when both declared and observed.
		if want.Enabled != nil && got.Enabled != nil {
			add("radio:"+band, "enabled", onOff(*want.Enabled), onOff(*got.Enabled))
		}
	}

	if items == nil {
		items = []DriftItem{} // never serialize as JSON null — clients iterate this
	}
	report := DriftReport{Items: items, InSync: true}
	for _, it := range items {
		if !it.InSync {
			report.InSync = false
			break
		}
	}
	return report
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// NormSecurity canonicalizes a security label so the user's shorthand
// ("wpa2-psk") and the device's form ("WPA2-PSK/AES") compare equal on the
// authentication mode (the cipher suffix is dropped).
func NormSecurity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "WPA2PSK", "WPA2-PSK")
	s = strings.ReplaceAll(s, "WPA3SAE", "WPA3-SAE")
	return s
}
