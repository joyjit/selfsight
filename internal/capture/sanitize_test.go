package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScrubStructural(t *testing.T) {
	s := &sanitizer{}
	in := []byte(`{"mac":"3C:37:86:AB:CD:EF","ip":"192.168.1.20","wan":"8.8.8.8"}`)
	got := string(s.scrub(in))

	if strings.Contains(got, "3C:37:86") {
		t.Errorf("real MAC OUI survived: %s", got)
	}
	if !strings.Contains(got, "AA:BB:CC:AB:CD:EF") {
		t.Errorf("MAC not mapped to doc range, last octets preserved: %s", got)
	}
	if strings.Contains(got, "192.168.1.20") {
		t.Errorf("private IP survived: %s", got)
	}
	if !strings.Contains(got, "192.0.2.20") {
		t.Errorf("private IP not mapped to TEST-NET-1 with last octet: %s", got)
	}
	if !strings.Contains(got, "8.8.8.8") {
		t.Errorf("public IP should be left alone: %s", got)
	}
}

func TestScrubLiteralsLongestFirst(t *testing.T) {
	s := &sanitizer{}
	s.literals = []replacement{
		{from: "NETGEAR-Kitchen", to: "example-ap-1"},
		{from: "NETGEAR", to: "example"},
	}
	// Sort mirrors newSanitizer: longest first.
	sortLiterals(s)
	got := string(s.scrub([]byte("ssid=NETGEAR-Kitchen host=NETGEAR")))
	if strings.Contains(got, "NETGEAR-Kitchen") {
		t.Errorf("longer literal not replaced first: %s", got)
	}
	if got != "ssid=example-ap-1 host=example" {
		t.Errorf("unexpected: %q", got)
	}
}

func TestScrubLiteralBeforeStructural(t *testing.T) {
	// A password that happens to contain digits must be replaced as a literal,
	// and IP-shaped substrings inside it should already be gone.
	s := &sanitizer{literals: []replacement{{from: "192.168.1.1-admin", to: "REDACTED"}}}
	got := string(s.scrub([]byte("token=192.168.1.1-admin")))
	if got != "token=REDACTED" {
		t.Errorf("literal should win over structural rewrite: %q", got)
	}
}

func TestScrubBoundaryAwareNoCorruption(t *testing.T) {
	// A short SSID value must scrub as a standalone JSON value but must not
	// corrupt unrelated words that merely contain it as a substring.
	s := &sanitizer{literals: []replacement{
		{from: "secure", to: "ExampleNet"},
		{from: "Hom", to: "ExampleNet2"},
	}}
	in := `{"ssid":"secure","mode":"secured","auth":"security","label":"Home","x":"Hom"}`
	got := string(s.scrub([]byte(in)))
	want := `{"ssid":"ExampleNet","mode":"secured","auth":"security","label":"Home","x":"ExampleNet2"}`
	if got != want {
		t.Errorf("boundary-aware scrub wrong:\n got=%s\nwant=%s", got, want)
	}
}

func TestScrubPrefixValuesLongestFirst(t *testing.T) {
	s := &sanitizer{}
	s.literals = []replacement{
		{from: "HOME-002E", to: "ExampleNet"},
		{from: "HOME-002E-2.4", to: "ExampleNet2"},
	}
	sortLiterals(s)
	got := string(s.scrub([]byte(`["HOME-002E","HOME-002E-2.4"]`)))
	if got != `["ExampleNet","ExampleNet2"]` {
		t.Errorf("prefix handling wrong: %q", got)
	}
}

func TestResidueCheckFlagsPrivateIP(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "leak.json"), []byte(`{"ip":"10.0.0.5"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &sanitizer{}
	res := s.scanResidue(dir)
	if len(res) == 0 {
		t.Fatal("expected residue check to flag a private IP that slipped through")
	}
}

// sortLiterals exposes newSanitizer's ordering for tests without a map file.
func sortLiterals(s *sanitizer) {
	for i := 1; i < len(s.literals); i++ {
		for j := i; j > 0 && len(s.literals[j].from) > len(s.literals[j-1].from); j-- {
			s.literals[j], s.literals[j-1] = s.literals[j-1], s.literals[j]
		}
	}
}
