package backup

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// vapKeyRe matches one wireless network's setting: band (wlan0 = 2.4 GHz),
// slot (vapN), field.
var vapKeyRe = regexp.MustCompile(`^system:vapSettings:vapSettingTable:(wlan\d+):(vap\d+):(.+)$`)

var bandLabels = map[string]string{"wlan0": "2.4 GHz", "wlan1": "5 GHz", "wlan2": "6 GHz"}

// Summarize turns a snapshot diff into plain-English sentences for the
// changes it understands — per-network events like a network being added,
// removed, hidden, or re-VLANed. A network event seen identically on every
// band collapses to one sentence; a single-band change is qualified with the
// band. Changes it does not understand are only counted (the raw diff below
// the summary carries them). Returns nil when nothing was summarizable.
func Summarize(from, to string) []string {
	a, b := parseSnapshot(from), parseSnapshot(to)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}

	unesc := strings.NewReplacer(`\ `, " ", `\:`, ":")
	type slotKey struct{ band, vap string }
	type fieldChange struct{ old, new string }
	slots := map[slotKey]map[string]fieldChange{}
	other := 0
	for k := range keys {
		if isVolatileKey(k) {
			continue
		}
		av, bv := a[k], b[k]
		if strings.Join(av, "\n") == strings.Join(bv, "\n") {
			continue
		}
		m := vapKeyRe.FindStringSubmatch(k)
		if m == nil || len(av) > 1 || len(bv) > 1 {
			other++
			continue
		}
		ch := fieldChange{}
		if len(av) == 1 {
			ch.old = unesc.Replace(av[0])
		}
		if len(bv) == 1 {
			ch.new = unesc.Replace(bv[0])
		}
		sk := slotKey{m[1], m[2]}
		if slots[sk] == nil {
			slots[sk] = map[string]fieldChange{}
		}
		slots[sk][m[3]] = ch
	}

	// The network's human name is its ssid value — from the older snapshot
	// when possible (a removed network only exists there).
	ssidName := func(sk slotKey, side map[string][]string) string {
		k := "system:vapSettings:vapSettingTable:" + sk.band + ":" + sk.vap + ":ssid"
		if v, ok := side[k]; ok && len(v) == 1 && v[0] != "" {
			return unesc.Replace(v[0])
		}
		return ""
	}

	// sentence -> set of bands it applies to
	lines := map[string]map[string]bool{}
	add := func(s, band string) {
		if lines[s] == nil {
			lines[s] = map[string]bool{}
		}
		lines[s][band] = true
	}

	for sk, fields := range slots {
		name := ssidName(sk, a)
		if name == "" {
			name = ssidName(sk, b)
		}
		if name == "" {
			name = sk.vap
		}
		q := `“` + name + `”`
		prof := fields["vapProfileName"]
		switch {
		// The slot's profile emptying/filling is the AP's signature for a
		// network being deleted or created; the slot's other field churn is
		// part of the same event, not separate news.
		case prof.new == "NONE" && prof.old != "" && prof.old != "NONE":
			add("Network "+q+" was removed", sk.band)
		case (prof.old == "NONE" || prof.old == "") && prof.new != "" && prof.new != "NONE":
			if n := ssidName(sk, b); n != "" {
				q = `“` + n + `”`
			}
			add("Network "+q+" was added", sk.band)
		default:
			for f, ch := range fields {
				switch f {
				case "ssid":
					add("Network “"+ch.old+"” was renamed to “"+ch.new+"”", sk.band)
				case "hideNetworkName":
					if ch.new == "1" {
						add("Network "+q+" was hidden (no longer broadcast)", sk.band)
					} else {
						add("Network "+q+" was made visible (broadcast again)", sk.band)
					}
				case "vapProfileStatus":
					if ch.new == "1" {
						add("Network "+q+" was turned on", sk.band)
					} else {
						add("Network "+q+" was turned off", sk.band)
					}
				case "vlanID":
					add("Network "+q+": VLAN "+ch.old+" → "+ch.new, sk.band)
				case "authenticationType", "encryption":
					add("Network "+q+": security settings changed", sk.band)
				default:
					add("Network "+q+": "+f+" "+ch.old+" → "+ch.new, sk.band)
				}
			}
		}
	}

	var out []string
	for s, bands := range lines {
		if len(bands) == 1 {
			for band := range bands {
				label := bandLabels[band]
				if label == "" {
					label = band
				}
				out = append(out, s+" ("+label+" only)")
			}
		} else {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if other > 0 && len(out) > 0 {
		out = append(out, fmt.Sprintf("…plus %d other low-level setting change(s), listed below.", other))
	}
	return out
}
