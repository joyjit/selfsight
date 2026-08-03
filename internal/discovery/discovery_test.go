package discovery

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/netip"
	"testing"
	"time"
)

func TestFingerprint(t *testing.T) {
	cases := []struct {
		name      string
		cn        string
		org       []string
		wantOK    bool
		wantModel string
	}{
		{"wax by CN", "WAX610", []string{"Netgear Inc."}, true, "WAX610"},
		{"netgear org only", "device", []string{"Netgear Inc."}, true, "device"},
		{"wax prefix no org", "WAX620", nil, true, "WAX620"},
		{"unrelated", "example.com", []string{"Acme"}, false, ""},
		{"empty", "", nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: c.cn, Organization: c.org}}
			model, ok := fingerprint(cert)
			if ok != c.wantOK || (ok && model != c.wantModel) {
				t.Errorf("fingerprint = (%q, %v), want (%q, %v)", model, ok, c.wantModel, c.wantOK)
			}
		})
	}
	if _, ok := fingerprint(nil); ok {
		t.Error("nil cert must not fingerprint")
	}
}

func TestHostsOf(t *testing.T) {
	hosts := hostsOf(netip.MustParsePrefix("192.168.1.0/30"))
	// /30 has 4 addresses; drop network (.0) and broadcast (.3) -> .1, .2.
	if len(hosts) != 2 || hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Errorf("hostsOf /30 = %v", hosts)
	}
	// /32 is a single host, kept as-is.
	if h := hostsOf(netip.MustParsePrefix("10.0.0.5/32")); len(h) != 1 || h[0] != "10.0.0.5" {
		t.Errorf("hostsOf /32 = %v", h)
	}
}

// TestSweepRefusesHugeRanges guards the memory ceiling: hostsOf materializes
// every address before probing, so an unbounded prefix would try to build
// billions of strings. The refusal must happen before any allocation.
func TestSweepRefusesHugeRanges(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "10.0.0.0/8", "::/0"} {
		if _, err := Sweep(context.Background(), cidr, 8, time.Millisecond); err == nil {
			t.Errorf("%s covers far more than the host limit and must be refused", cidr)
		}
	}
	// A realistic LAN range stays allowed (no AP answers, so it finds nothing).
	if _, err := Sweep(context.Background(), "192.0.2.0/30", 8, time.Millisecond); err != nil {
		t.Errorf("an ordinary /30 must still be scannable: %v", err)
	}
}
