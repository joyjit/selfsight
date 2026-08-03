// Package discovery finds WAX access points on a subnet without credentials.
//
// It is the cheapest tier of the planned discovery (DESIGN.md, "Discovery"): a
// TCP+TLS probe of each host's HTTPS port, fingerprinting NETGEAR APs from the
// self-signed certificate the device presents pre-auth (subject CN like
// "WAX610", organization "Netgear Inc."). Found candidates feed the normal
// add-device flow. It is read-only — a handshake and nothing more.
package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Candidate is a host that fingerprinted as a NETGEAR AP.
type Candidate struct {
	IP    string `json:"ip"`
	Model string `json:"model"` // from the cert CN, e.g. "WAX610"
}

// fingerprint inspects a presented certificate and reports the AP model if it
// looks like a NETGEAR WAX device. Kept separate so it is unit-testable without
// a network.
func fingerprint(cert *x509.Certificate) (model string, ok bool) {
	if cert == nil {
		return "", false
	}
	org := strings.Join(cert.Subject.Organization, " ")
	cn := cert.Subject.CommonName
	isNetgear := strings.Contains(strings.ToLower(org), "netgear")
	looksWAX := strings.HasPrefix(strings.ToUpper(cn), "WAX")
	if isNetgear || looksWAX {
		if cn == "" {
			cn = "unknown"
		}
		return cn, true
	}
	return "", false
}

// probe does a single TLS handshake and fingerprints the cert. It never verifies
// the cert (devices are self-signed); it only reads the identifying fields.
func probe(ctx context.Context, ip string, port string, timeout time.Duration) (Candidate, bool) {
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return Candidate{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: ip}) //nolint:gosec // fingerprinting self-signed device certs
	if err := tc.HandshakeContext(ctx); err != nil {
		return Candidate{}, false
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Candidate{}, false
	}
	if model, ok := fingerprint(certs[0]); ok {
		return Candidate{IP: ip, Model: model}, true
	}
	return Candidate{}, false
}

// MaxSweepHosts caps how large a range Sweep will scan. hostsOf materializes
// every address in the range before probing starts, so an unbounded prefix
// (say 0.0.0.0/0) would try to build billions of strings and exhaust memory
// long before the first probe. A /16 is already 65k hosts — far beyond any
// network these APs live on, and minutes of scanning.
const MaxSweepHosts = 1 << 16

// Sweep probes every host in cidr concurrently and returns the WAX APs found,
// sorted by IP. The network and broadcast addresses are skipped.
func Sweep(ctx context.Context, cidr string, concurrency int, timeout time.Duration) ([]Candidate, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("discovery: bad CIDR %q: %w", cidr, err)
	}
	if n := prefixSize(prefix); n > MaxSweepHosts {
		return nil, fmt.Errorf("discovery: %s covers %d addresses, more than the %d-host limit — scan a smaller range", cidr, n, MaxSweepHosts)
	}
	if concurrency <= 0 {
		concurrency = 64
	}
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}

	hosts := hostsOf(prefix)
	sem := make(chan struct{}, concurrency)
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []Candidate
	)
	for _, ip := range hosts {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if c, ok := probe(ctx, ip, "443", timeout); ok {
				mu.Lock()
				out = append(out, c)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out, nil
}

// hostsOf returns the usable host addresses in a prefix (skipping the network
// and broadcast addresses for IPv4 prefixes shorter than /31).
// prefixSize counts the addresses a prefix covers, saturating at a value above
// MaxSweepHosts so an enormous prefix (an IPv6 /0 has 2^128 addresses) is
// reported as too large instead of overflowing.
func prefixSize(p netip.Prefix) uint64 {
	bits := p.Addr().BitLen() - p.Bits()
	if bits < 0 {
		return 0
	}
	if bits >= 64 || uint64(1)<<bits > MaxSweepHosts {
		return MaxSweepHosts + 1
	}
	return uint64(1) << bits
}

func hostsOf(p netip.Prefix) []string {
	p = p.Masked()
	var all []string
	for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
		all = append(all, addr.String())
	}
	if p.Addr().Is4() && p.Bits() <= 30 && len(all) >= 2 {
		all = all[1 : len(all)-1] // drop network + broadcast
	}
	return all
}
