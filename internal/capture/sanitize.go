package capture

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RunSanitize scrubs a raw capture directory into committable fixtures.
//
// It is a scripted pass (never manual editing), so it is repeatable and
// auditable. Two layers run over every file:
//
//  1. Structural regexes replace anything with a recognizable shape - MAC
//     addresses and IPv4 addresses - with deterministic fakes drawn from
//     documentation ranges (MAC AA:BB:CC:*, IP 192.0.2.0/24, TEST-NET-1).
//  2. A user-supplied map (--map) replaces literal secrets the tool cannot
//     recognize by shape: serials, SSIDs, hostnames, usernames, passwords,
//     session tokens. Longest keys first, so substrings never clobber wider
//     matches.
//
// Byte structure is otherwise preserved: this is search-and-replace, not
// reformatting, so the sanitized transcript stays a faithful protocol record.
//
// This does not prove the output is clean. Every file is eyeballed before it
// is committed; the sanitizer is a YELLOW-tier tool per AGENTS.md. --check
// reports any residue the built-in patterns still see, as a backstop - not a
// guarantee.
func RunSanitize(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	inDir := fs.String("in", "", "raw capture directory to read (required)")
	outDir := fs.String("out", "", "directory to write sanitized files into (required)")
	mapPath := fs.String("map", "", "YAML file of literal real->fake replacements (recommended)")
	check := fs.Bool("check", true, "after writing, scan output for residue that looks unsanitized")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: selfsight sanitize --in <rawdir> --out <fixturedir> [--map map.yaml]

Scrubs raw captures into fixtures. MACs and IPv4 addresses are replaced by
shape; everything else (serials, SSIDs, hostnames, credentials, tokens) must be
listed in --map as real->fake pairs. Example map.yaml:

  replace:
    "NETGEAR-Kitchen": "example-ap-1"
    "5ND1234ABCDEF":    "SERIAL0000001"
    "admin":            "admin"           # keep, or change
    "s3cret-passphrase": "REDACTED-PASS"

Then eyeball every output file before committing (git history is permanent).
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" || *outDir == "" {
		fs.Usage()
		return errors.New("--in and --out are required")
	}
	if filepath.Clean(*inDir) == filepath.Clean(*outDir) {
		return errors.New("--in and --out must differ (never sanitize in place)")
	}

	s, err := newSanitizer(*mapPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	entries, err := os.ReadDir(*inDir)
	if err != nil {
		return fmt.Errorf("read in dir: %w", err)
	}

	var written int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(*inDir, e.Name()))
		if err != nil {
			return fmt.Errorf("read %s: %w", e.Name(), err)
		}
		clean := s.scrub(raw)
		if err := os.WriteFile(filepath.Join(*outDir, e.Name()), clean, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", e.Name(), err)
		}
		written++
	}

	fmt.Fprintf(os.Stderr, "sanitize: wrote %d file(s) to %s\n", written, *outDir)

	if *check {
		residue := s.scanResidue(*outDir)
		if len(residue) > 0 {
			fmt.Fprintln(os.Stderr, "sanitize: WARNING - output still contains values that look unsanitized:")
			for _, r := range residue {
				fmt.Fprintf(os.Stderr, "  %s\n", r)
			}
			fmt.Fprintln(os.Stderr, "sanitize: add these to --map (or confirm they are already fake), then re-run.")
			return errors.New("residue detected; review before committing")
		}
		fmt.Fprintln(os.Stderr, "sanitize: no known-shape residue detected. Still eyeball every file before commit.")
	}
	return nil
}

// sanitizer holds the compiled structural rules and the literal replacement map.
type sanitizer struct {
	literals []replacement             // longest key first
	reCache  map[string]*regexp.Regexp // boundary regex per literal (nil = no caching)
}

type replacement struct {
	from string
	to   string
}

// macRe matches colon- or dash-separated MAC addresses.
var macRe = regexp.MustCompile(`(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)

// ipv4Re matches dotted-quad IPv4 addresses.
var ipv4Re = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)

type sanitizeMap struct {
	Replace map[string]string `yaml:"replace"`
}

func newSanitizer(mapPath string) (*sanitizer, error) {
	s := &sanitizer{reCache: map[string]*regexp.Regexp{}}
	if mapPath == "" {
		return s, nil
	}
	data, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("read map: %w", err)
	}
	var m sanitizeMap
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse map: %w", err)
	}
	for from, to := range m.Replace {
		if from == "" {
			continue
		}
		s.literals = append(s.literals, replacement{from: from, to: to})
	}
	// Longest keys first so "NETGEAR-Kitchen" is replaced before "NETGEAR".
	sort.Slice(s.literals, func(i, j int) bool {
		return len(s.literals[i].from) > len(s.literals[j].from)
	})
	return s, nil
}

// scrub applies literal replacements first (so a mapped value is gone before a
// structural rule could partially rewrite it), then the structural rules.
//
// Literal replacement is boundary-aware: a mapped value is only replaced when it
// is not embedded in a larger alphanumeric run, so a short SSID like "secure"
// scrubs the standalone value but never corrupts "secured" or "security". Values
// bounded by quotes, commas, spaces, or punctuation (i.e. every JSON string
// value and header token) still match. Longest keys run first, so a value that
// is a prefix of another mapped value (e.g. "HOME-002E" vs "HOME-002E-2.4") is
// handled by the longer one before the shorter can match it.
func (s *sanitizer) scrub(in []byte) []byte {
	out := string(in)
	for _, r := range s.literals {
		out = s.boundaryReplace(out, r.from, r.to)
	}
	out = macRe.ReplaceAllStringFunc(out, fakeMAC)
	out = ipv4Re.ReplaceAllStringFunc(out, fakeIPv4)
	return []byte(out)
}

// boundaryReplace replaces every occurrence of from with to, but only where from
// is not flanked by an ASCII alphanumeric on either side. It caches the compiled
// regex per literal so repeated calls across many files stay cheap.
func (s *sanitizer) boundaryReplace(text, from, to string) string {
	if from == "" {
		return text
	}
	re := s.reCache[from]
	if re == nil {
		// (^|[^0-9A-Za-z]) <value> ($|[^0-9A-Za-z]); the boundary chars are
		// captured and re-emitted so only the value itself is swapped.
		re = regexp.MustCompile(`(^|[^0-9A-Za-z])` + regexp.QuoteMeta(from) + `($|[^0-9A-Za-z])`)
		if s.reCache != nil {
			s.reCache[from] = re
		}
	}
	repl := "${1}" + escapeRepl(to) + "${2}"
	// A single pass can miss back-to-back matches that share one boundary char;
	// loop until stable (bounded — each pass strictly reduces occurrences).
	for {
		next := re.ReplaceAllString(text, repl)
		if next == text {
			return text
		}
		text = next
	}
}

// escapeRepl neutralizes $ in a replacement literal so regexp doesn't treat it as
// a capture reference. Our fakes contain no $, but real map values might.
func escapeRepl(s string) string {
	return strings.ReplaceAll(s, "$", "$$")
}

// fakeMAC maps any MAC to a deterministic address in the AA:BB:CC:* space,
// keyed on the last three octets so distinct devices stay distinct.
func fakeMAC(m string) string {
	sep := ":"
	if strings.Contains(m, "-") {
		sep = "-"
	}
	parts := regexp.MustCompile(`[:-]`).Split(m, -1)
	tail := parts[3:] // preserve the low 3 octets; they carry no vendor identity
	return strings.Join(append([]string{"AA", "BB", "CC"}, tail...), sep)
}

// fakeIPv4 maps private/link-local addresses into the TEST-NET-1 documentation
// range (192.0.2.0/24), preserving the last octet so hosts stay distinguishable.
// Public and already-documentation addresses are left alone.
func fakeIPv4(ip string) string {
	m := ipv4Re.FindStringSubmatch(ip)
	if m == nil {
		return ip
	}
	if !isPrivateV4(m[1], m[2]) {
		return ip
	}
	return "192.0.2." + m[4]
}

func isPrivateV4(a, b string) bool {
	switch a {
	case "10":
		return true
	case "192":
		return b == "168"
	case "172":
		// 172.16.0.0 - 172.31.255.255
		return b >= "16" && b <= "31" && len(b) == 2
	case "169":
		return b == "254" // link-local
	}
	return false
}

// scanResidue re-reads the output and reports any MAC/IPv4 that isn't already a
// documentation-range fake. It is a backstop for the map, not a clean bill.
func (s *sanitizer) scanResidue(dir string) []string {
	seen := map[string]bool{}
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{fmt.Sprintf("(could not re-read %s: %v)", dir, err)}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		text := string(data)
		for _, mac := range macRe.FindAllString(text, -1) {
			if !strings.HasPrefix(strings.ToUpper(mac), "AA:BB:CC") &&
				!strings.HasPrefix(strings.ToUpper(mac), "AA-BB-CC") && !seen[mac] {
				seen[mac] = true
				out = append(out, fmt.Sprintf("%s: MAC %s", e.Name(), mac))
			}
		}
		for _, ip := range ipv4Re.FindAllString(text, -1) {
			m := ipv4Re.FindStringSubmatch(ip)
			if isPrivateV4(m[1], m[2]) && !seen[ip] {
				seen[ip] = true
				out = append(out, fmt.Sprintf("%s: private IP %s", e.Name(), ip))
			}
		}
	}
	sort.Strings(out)
	return out
}
