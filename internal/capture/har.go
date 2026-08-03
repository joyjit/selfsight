package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RunImportHAR converts a browser DevTools HAR export into raw request/response
// pairs in the same numbered format the capture proxy produces, ready for
// `selfsight sanitize`.
//
// This is the recommended way to record a first live session: drive the AP's
// real web UI with DevTools open (real TLS, real cookies, no proxy in the
// middle), then "Save all as HAR". It sidesteps every reverse-proxy pitfall
// (Secure cookies, absolute redirects, mixed content).
//
// The HAR is raw and contains secrets; output goes outside the repo by default,
// and must be run through `selfsight sanitize` before anything is committed.
func RunImportHAR(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("import-har", flag.ContinueOnError)
	inPath := fs.String("in", "", "HAR file exported from browser DevTools (required)")
	outDir := fs.String("out", defaultCaptureDir(), "directory to write raw request/response pairs into")
	host := fs.String("host", "", "only import entries whose URL contains this string, e.g. the AP IP (recommended)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: selfsight import-har --in capture.har [--host <ap-ip>] [--out dir]

Converts a DevTools HAR export into raw request/response pairs. In Chrome/Edge/
Firefox: open DevTools -> Network, check "Preserve log", drive the AP UI (log
in; view status/system, clients, radios; read config; and an Insight-managed AP
for the status-100 case), then right-click the request list -> "Save all as HAR".

Pass --host <ap-ip> to drop analytics/CDN noise. Output is RAW (secrets) - run
'selfsight sanitize' next.
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		fs.Usage()
		return errors.New("--in is required")
	}

	data, err := os.ReadFile(*inPath)
	if err != nil {
		return fmt.Errorf("read HAR: %w", err)
	}
	var har harFile
	if err := json.Unmarshal(data, &har); err != nil {
		return fmt.Errorf("parse HAR: %w", err)
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	var n int
	for _, e := range har.Log.Entries {
		if *host != "" && !strings.Contains(e.Request.URL, *host) {
			continue
		}
		n++
		base := filepath.Join(*outDir, fmt.Sprintf("%04d", n))
		if err := os.WriteFile(base+".request.txt", []byte(renderRequest(e.Request)), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(base+".response.txt", []byte(renderResponse(e.Response)), 0o600); err != nil {
			return err
		}
	}

	if n == 0 {
		if *host != "" {
			return fmt.Errorf("no HAR entries matched --host %q", *host)
		}
		return errors.New("HAR contained no entries")
	}
	fmt.Fprintf(os.Stderr, "import-har: wrote %d exchange(s) to %s\n", n, *outDir)
	fmt.Fprintln(os.Stderr, "import-har: raw output contains secrets - run 'selfsight sanitize' before committing.")
	return nil
}

// HAR types: only the fields we need. Unlisted fields are ignored.
type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	HTTPVer  string      `json:"httpVersion"`
	Headers  []harHeader `json:"headers"`
	PostData struct {
		Text string `json:"text"`
	} `json:"postData"`
}

type harResponse struct {
	Status     int         `json:"status"`
	StatusText string      `json:"statusText"`
	HTTPVer    string      `json:"httpVersion"`
	Headers    []harHeader `json:"headers"`
	Content    struct {
		Text     string `json:"text"`
		Encoding string `json:"encoding"`
	} `json:"content"`
}

func renderRequest(r harRequest) string {
	var b strings.Builder
	ver := orDefault(r.HTTPVer, "HTTP/1.1")
	fmt.Fprintf(&b, "%s %s %s\r\n", r.Method, r.URL, ver)
	writeHeaders(&b, r.Headers)
	b.WriteString("\r\n")
	b.WriteString(r.PostData.Text)
	return b.String()
}

func renderResponse(r harResponse) string {
	var b strings.Builder
	ver := orDefault(r.HTTPVer, "HTTP/1.1")
	fmt.Fprintf(&b, "%s %d %s\r\n", ver, r.Status, r.StatusText)
	writeHeaders(&b, r.Headers)
	b.WriteString("\r\n")
	body := r.Content.Text
	if r.Content.Encoding == "base64" {
		if dec, err := base64.StdEncoding.DecodeString(body); err == nil {
			body = string(dec)
		}
	}
	b.WriteString(body)
	return b.String()
}

func writeHeaders(b *strings.Builder, headers []harHeader) {
	for _, h := range headers {
		// DevTools includes HTTP/2 pseudo-headers (:method, :path); skip them.
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		fmt.Fprintf(b, "%s: %s\r\n", h.Name, h.Value)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
