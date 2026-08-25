// Package wax is the driver for NETGEAR WAX-series access points.
//
// Everything the AP exposes goes through one endpoint, POST /socketCommunication
// (see testdata/wax610/ and DESIGN.md, "The WAX driver"). A read sends the exact
// config subtree with empty-string leaves; the response echoes the shape filled
// in, wrapped in an envelope whose body `status` — not the HTTP code — says
// whether it worked.
//
// This file owns transport, session signing, and the status envelope. Typed
// reads live in read.go. Every behavior here is backed by a sanitized transcript
// under testdata/wax610/.
package wax

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	neturl "net/url"
	"selfsight/internal/device"
	"strconv"
	"strings"
	"time"
)

const socketPath = "/socketCommunication"

// Client talks to one WAX access point. A zero Client is not usable; build one
// with New. A Client is safe for sequential use; it holds one warm session.
type Client struct {
	host         string // as configured: an IP or a DNS name, optional :port
	dial         string // what is actually dialed: host with any name resolved to an IP
	http         *http.Client
	token        string        // security token; sent raw in the `security` header
	sid          string        // lhttpdsid session cookie
	pollInterval time.Duration // firmware-upgrade poll cadence
	pinPath      string        // TOFU certificate pin file ("" = pinning off)
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client (mainly for tests).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithPollInterval overrides the firmware-upgrade poll cadence (tests).
func WithPollInterval(d time.Duration) Option {
	return func(c *Client) { c.pollInterval = d }
}

// New builds a Client for the AP at host (an IP or hostname, no scheme).
//
// Device certificates are self-signed, so chain verification is off — the
// trust model the AP's own web UI uses (DESIGN.md, "Security"). WithPinPath
// upgrades that to trust-on-first-use pinning of the device certificate.
func New(host string, opts ...Option) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // device self-signed certs, by design
	}
	own := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	c := &Client{host: host, pollInterval: 5 * time.Second, http: own}
	for _, o := range opts {
		o(c)
	}
	// Pinning hooks into our own transport; a caller-supplied client (tests)
	// brings its own trust and is left alone.
	if c.pinPath != "" && c.http == own {
		// VerifyPeerCertificate is skipped on a resumed TLS session, which
		// would let a resumed connection dodge the pin check. It cannot happen
		// here: Go only resumes when tls.Config.ClientSessionCache is set,
		// net/http never sets one, and neither do we — so every connection is
		// a full handshake and the pin is always checked. Keep it that way; if
		// a session cache is ever added, move this to VerifyConnection, which
		// runs on resumed handshakes too.
		//nolint:gosec // G123: resumption is off, see above.
		tr.TLSClientConfig.VerifyPeerCertificate = c.verifyPin
	}
	return c
}

// base returns the URL root the client dials, always with an IP for the host.
// WAX APs misbehave when addressed by DNS name: the API answers status 1
// ("Internal error") to any request whose Host header is a name, and the
// self-signed device certificate names no hosts at all — so a name in config
// is for humans, and the wire always carries the resolved IP (observed live
// 2026-07-27). The resolution is cached; a transport failure drops the cache
// so a device renumbered by DHCP heals on the next attempt.
func (c *Client) base(ctx context.Context) (string, error) {
	if c.dial == "" {
		d, err := dialAddr(ctx, c.host)
		if err != nil {
			return "", fmt.Errorf("wax: resolve %s: %w", c.host, err)
		}
		c.dial = d
	}
	return "https://" + c.dial, nil
}

// forgetDial drops the cached name resolution after a transport failure, so
// the next request re-resolves instead of retrying a possibly stale address.
func (c *Client) forgetDial() { c.dial = "" }

// dialAddr turns a configured host (IP or DNS name, optional :port) into the
// address to dial: names are resolved to an IP, IPv4 preferred, IPs pass
// through untouched.
func dialAddr(ctx context.Context, host string) (string, error) {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		h, port = host, ""
	}
	if net.ParseIP(h) == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, h)
		if err != nil {
			return "", err
		}
		h = addrs[0]
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				h = a
				break
			}
		}
	}
	if port != "" {
		return net.JoinHostPort(h, port), nil
	}
	if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
		return "[" + h + "]", nil // bare IPv6 needs brackets in a URL
	}
	return h, nil
}

// SetSession installs a warm session (a token + lhttpdsid cookie). Reads fail
// with ErrAuthExpired until a valid session is set (via SetSession or Login).
func (c *Client) SetSession(token, lhttpdsid string) {
	c.token = token
	c.sid = lhttpdsid
}

// Session returns the current warm session for persisting and later reuse.
func (c *Client) Session() Session { return Session{Token: c.token, LHTTPDSID: c.sid} }

// Login authenticates with admin credentials and installs the resulting warm
// session on the Client — no browser required.
//
// The AP's login must run inside a lighttpd session the device itself started:
// a "cold" credential POST returns a token whose session reads back as locked
// (status 100). So Login mirrors the browser's bootstrap — GET the login page
// first (through a cookie jar, which seeds the httpOnly lhttpdsid), then POST
// the credentials within that same jar. The reply carries the security token in
// its body; lhttpdsid comes from the jar.
//
// Each login consumes one of the AP's limited login slots, so callers should
// persist and reuse the session (see Session / SetSession) rather than log in
// per call.
func (c *Client) Login(ctx context.Context, user, password string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	// A login-only client that shares our transport but keeps a cookie jar, so
	// the seed cookie from the GET is replayed on the login POST.
	lc := &http.Client{Timeout: c.http.Timeout, Transport: c.http.Transport, Jar: jar}

	base, err := c.base(ctx)
	if err != nil {
		return err
	}
	// 1. GET the login page so the AP establishes a lighttpd session (lhttpdsid).
	if greq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/AP_login", nil); err == nil {
		if gresp, err := lc.Do(greq); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(gresp.Body, 1<<20))
			_ = gresp.Body.Close()
		}
	}

	// 2. POST credentials inside that session.
	payload, err := json.Marshal(map[string]any{
		"system": map[string]any{
			"basicSettings": map[string]any{"adminName": user, "adminPasswd": password},
		},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+socketPath, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("time", timeHeader())

	resp, err := lc.Do(req)
	if err != nil {
		c.forgetDial()
		return fmt.Errorf("wax: login: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	var lr struct {
		Status apiStatus `json:"status"`
		System struct {
			SecurityToken string `json:"security_token"`
		} `json:"system"`
	}
	if err := json.Unmarshal(body, &lr); err != nil {
		return fmt.Errorf("wax: login: bad response (HTTP %d): %w", resp.StatusCode, err)
	}
	if err := lr.Status.err(); err != nil {
		return fmt.Errorf("wax: login failed: %w", err)
	}
	if lr.System.SecurityToken == "" {
		return errors.New("wax: login: response carried no security_token")
	}

	// lhttpdsid is the session cookie now held in the jar for this host.
	var sid string
	if u, err := neturl.Parse(base + "/"); err == nil {
		for _, ck := range jar.Cookies(u) {
			if ck.Name == "lhttpdsid" {
				sid = ck.Value
			}
		}
	}
	if sid == "" {
		return errors.New("wax: login: no lhttpdsid cookie was established")
	}
	c.token = lr.System.SecurityToken
	c.sid = sid
	return nil
}

// Protocol status codes, returned in the response body envelope.
var (
	// ErrManaged is status 100. It means the local API is locked — either the
	// device is genuinely Insight-managed, OR the warm session is dead/displaced
	// (a stale session reads back as 100, not 401). A caller reusing a saved
	// session should treat 100 as "re-login"; only 100 from a freshly minted
	// session means the device is truly Insight-managed.
	ErrManaged = fmt.Errorf("wax: local API locked — Insight-managed or dead session (status 100): %w", device.ErrManaged)
	// ErrAuthExpired means the session is dead and must be re-minted.
	ErrAuthExpired = errors.New("wax: session expired or unauthenticated (status 401)")
	// ErrBadRequest means the request named unknown keys (all-or-nothing).
	ErrBadRequest = errors.New("wax: request rejected, unknown keys (status 1)")
)

// APIError is any non-zero envelope status without a named sentinel above.
type APIError struct{ Status int }

func (e *APIError) Error() string { return fmt.Sprintf("wax: API status %d", e.Status) }

// apiStatus tolerates the envelope status arriving as a JSON number or a quoted
// string (the AP is inconsistent, and transport failures surface as "error").
type apiStatus int

func (s *apiStatus) UnmarshalJSON(b []byte) error {
	t := strings.Trim(string(b), `"`)
	if t == "" || t == "error" {
		return errors.New("wax: transport error / empty status")
	}
	n, err := strconv.Atoi(t)
	if err != nil {
		return fmt.Errorf("wax: unparseable status %q", t)
	}
	*s = apiStatus(n)
	return nil
}

func (s apiStatus) err() error {
	switch int(s) {
	case 0:
		return nil
	case 1:
		return ErrBadRequest
	case 100:
		return ErrManaged
	case 401:
		return ErrAuthExpired
	default:
		return &APIError{Status: int(s)}
	}
}

// socket POSTs a read payload to /socketCommunication, checks the envelope
// status, and unmarshals the full response body into out (which must embed the
// status envelope plus the subtree it wants). out may be nil to only check status.
func (c *Client) socket(ctx context.Context, payload string, out any) error {
	base, err := c.base(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+socketPath, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	c.sign(req)

	resp, err := c.http.Do(req)
	if err != nil {
		c.forgetDial()
		return fmt.Errorf("wax: POST %s: %w", socketPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}

	var env struct {
		Status apiStatus `json:"status"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("wax: bad response (HTTP %d): %w", resp.StatusCode, err)
	}
	if err := env.Status.err(); err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("wax: decode response: %w", err)
		}
	}
	return nil
}

// postSigned does a warm-jar-signed POST to an arbitrary path and, if out is
// non-nil, decodes the JSON body into it. Unlike socket() it does not interpret
// the status envelope — callers that need it (backup, firmware) inspect the
// decoded fields themselves. Transport failures return an error.
func (c *Client) postSigned(ctx context.Context, path, body string, out any) error {
	base, err := c.base(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	c.sign(req)
	resp, err := c.http.Do(req)
	if err != nil {
		c.forgetDial()
		return fmt.Errorf("wax: POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("wax: POST %s: decode: %w", path, err)
		}
	}
	return nil
}

// sign applies warm-jar auth to a request: the raw token in a `security` header
// and the cookie jar `lhttpdsid=…; ssid=base64(token)`. Deliberately NO `time`
// header — the time header selects the "Insight-validated" path, which returns
// status 100 on a managed AP; the warm-jar path returns real data even while the
// device is managed. No-op if there is no session.
func (c *Client) sign(req *http.Request) {
	if c.token == "" {
		return
	}
	sec := base64.StdEncoding.EncodeToString([]byte(c.token))
	req.Header.Set("security", c.token)
	req.Header.Set("Cookie", fmt.Sprintf("lhttpdsid=%s; ssid=%s", c.sid, sec))
}

// timeHeader matches the AP UI's `time` header on the login request: a
// wall-clock ~45 min ahead, formatted like "Sat Jul 11 2026 03:56:42 GMT".
func timeHeader() string {
	return time.Now().UTC().Add(45 * time.Minute).Format("Mon Jan 02 2006 15:04:05 GMT")
}
