// Package capture provides the two protocol-retirement tools: a logging
// reverse proxy that records real AP HTTP exchanges, and a scripted sanitizer
// that scrubs those recordings into committable fixtures.
//
// The proxy is deliberately endpoint-agnostic: it forwards whatever a client
// (a browser, or a curl script) sends to the AP and records every
// request/response pair verbatim. It bakes in no assumption about the WAX API,
// so it can retire protocol risk instead of encoding a guess. See DESIGN.md,
// "Testing and fixtures".
package capture

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// RunCapture starts a recording reverse proxy in front of one AP.
//
// Point a browser (or a script) at the proxy's listen address over plain HTTP;
// every request is forwarded to the target AP over HTTPS (its self-signed cert
// is not verified, matching how the driver talks to devices) and both the
// request and response are written to the output directory as a numbered pair:
//
//	0001.request.txt   0001.response.txt
//	0002.request.txt   0002.response.txt
//
// Raw captures contain real MACs, serials, SSIDs, IPs and credentials. They
// MUST NOT enter the repository; run `selfsight sanitize` first. The default
// output directory lives under the OS temp dir, never inside the repo.
func RunCapture(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	target := fs.String("target", "", "AP base URL to record, e.g. https://192.0.2.20 (required)")
	listen := fs.String("listen", "127.0.0.1:9100", "address the proxy listens on (plain HTTP)")
	outDir := fs.String("out", defaultCaptureDir(), "directory to write raw request/response pairs into")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: selfsight capture --target https://<ap-ip> [--listen host:port] [--out dir]

Records real AP HTTP exchanges through a logging reverse proxy. Point your
browser at the listen address and drive the AP's local web UI (log in, view
status, clients, radios, read config, and the Insight-managed status-100 case).

Output is RAW and contains secrets. Never commit it. Run 'selfsight sanitize'
to produce fixtures for testdata/wax610/.
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		fs.Usage()
		return errors.New("--target is required")
	}

	targetURL, err := url.Parse(*target)
	if err != nil {
		return fmt.Errorf("bad --target: %w", err)
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		return fmt.Errorf("bad --target %q: need a scheme and host, e.g. https://192.0.2.20", *target)
	}

	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	rec := &recorder{dir: *outDir}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// Device certs are self-signed; skip verification for device connections
	// exactly as the real driver will (DESIGN.md, "Security").
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // device self-signed certs, by design
	}
	// Preserve the AP's expected Host header so login/session behavior matches.
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = targetURL.Host
	}
	proxy.ModifyResponse = rec.record

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 15 * time.Second,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}

	fmt.Fprintf(os.Stderr, "capture: recording %s  ->  %s\n", *listen, targetURL)
	fmt.Fprintf(os.Stderr, "capture: writing pairs to %s\n", *outDir)
	fmt.Fprintf(os.Stderr, "capture: point your browser at http://%s and drive the AP UI; Ctrl-C when done.\n", *listen)
	fmt.Fprintln(os.Stderr, "capture: raw output contains secrets - run 'selfsight sanitize' before committing.")

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		fmt.Fprintf(os.Stderr, "\ncapture: recorded %d exchange(s) to %s\n", rec.count.Load(), *outDir)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// recorder writes each request/response pair to disk as it flows through.
type recorder struct {
	dir   string
	count atomic.Int64
}

func (rec *recorder) record(resp *http.Response) error {
	n := rec.count.Add(1)
	base := filepath.Join(rec.dir, fmt.Sprintf("%04d", n))

	// Request: dump with body. DumpRequestOut would re-serialize; the response's
	// Request has the outbound form we want to record.
	if reqDump, err := httputil.DumpRequest(resp.Request, true); err == nil {
		_ = os.WriteFile(base+".request.txt", reqDump, 0o600)
	}

	// Response: buffer the body so we can both record it and let it flow on.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	// Dump status line + headers only (body=false leaves resp.Body intact), then
	// append the buffered body ourselves so the recorded bytes match what the AP
	// actually sent. Reset the body afterwards so it still flows to the client.
	resp.Body = io.NopCloser(bytes.NewReader(body))
	head, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	out := append(head, body...)
	_ = os.WriteFile(base+".response.txt", out, 0o600)
	return nil
}

func defaultCaptureDir() string {
	return filepath.Join(os.TempDir(), "selfsight-capture")
}
