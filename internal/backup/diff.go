package backup

import (
	"sort"
	"strings"
)

// unifiedDiff produces a readable diff between two snapshots. Snapshots are
// sorted, one-setting-per-line config text ("key value", spaces and colons in
// values backslash-escaped), so settings can be compared key by key:
//
//	~ key old → new    the setting changed
//	+ key value        the setting only exists in the newer snapshot
//	- key value        the setting only exists in the older snapshot
//
// The leading "system:" (shared by every key) is dropped and value escapes
// are undone — this output is for humans, not machines.
func unifiedDiff(from, to string) string {
	a, b := parseSnapshot(from), parseSnapshot(to)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	unesc := strings.NewReplacer(`\ `, " ", `\:`, ":")
	var out []string
	for _, k := range sorted {
		// Volatile bookkeeping (self-updating timestamps) is not a change
		// anyone made — hide it even in snapshots recorded before
		// StableConfig started blanking it.
		if isVolatileKey(k) {
			continue
		}
		av, bv := a[k], b[k]
		if strings.Join(av, "\n") == strings.Join(bv, "\n") {
			continue
		}
		disp := strings.TrimPrefix(k, "system:")
		if len(av) == 1 && len(bv) == 1 {
			out = append(out, "~ "+disp+" "+unesc.Replace(av[0])+" → "+unesc.Replace(bv[0]))
			continue
		}
		// A key with several values (or present on one side only): plain
		// removed/added lines.
		inB := map[string]bool{}
		for _, v := range bv {
			inB[v] = true
		}
		inA := map[string]bool{}
		for _, v := range av {
			inA[v] = true
		}
		for _, v := range av {
			if !inB[v] {
				out = append(out, "- "+disp+" "+unesc.Replace(v))
			}
		}
		for _, v := range bv {
			if !inA[v] {
				out = append(out, "+ "+disp+" "+unesc.Replace(v))
			}
		}
	}
	return strings.Join(out, "\n")
}

// parseSnapshot splits snapshot text into key -> values. The key runs to the
// first unescaped space; the rest of the line is the (still-escaped) value.
// Values per key keep their order so multi-value keys compare stably.
func parseSnapshot(s string) map[string][]string {
	m := map[string][]string{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		key, val := l, ""
		for i := 0; i < len(l); i++ {
			if l[i] == '\\' {
				i++ // skip the escaped character
				continue
			}
			if l[i] == ' ' {
				key, val = l[:i], l[i+1:]
				break
			}
		}
		m[key] = append(m[key], val)
	}
	return m
}
