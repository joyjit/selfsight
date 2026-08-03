// Command selfsight is the single binary for the selfsight AP manager.
//
// Subcommands:
//
//	selfsight [serve]        run the server + dashboard
//	selfsight probe <ip>     log into one AP, print its status as JSON
//	selfsight discover <cidr> scan a subnet for APs, without logging in
//	selfsight capture        record real AP HTTP exchanges through a logging proxy
//	selfsight import-har     turn a browser HAR export into raw request/response pairs
//	selfsight sanitize       scrub a capture directory into committable fixtures
//	selfsight version        print the build version
//
// The protocol is retired first (capture -> sanitize -> fixtures); the driver,
// server, and dashboard are written to satisfy those fixtures. See DESIGN.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"selfsight/internal/api"
	"selfsight/internal/capture"
	"selfsight/internal/core"
	"selfsight/internal/discovery"
	"selfsight/internal/driver/wax"
	"selfsight/web"
)

// version is the build version, set at release time with
// -ldflags "-X main.version=<tag>". Unset builds report "dev".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "selfsight: "+err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return runServer(ctx, nil)
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "capture":
		return capture.RunCapture(ctx, rest)
	case "import-har":
		return capture.RunImportHAR(ctx, rest)
	case "sanitize":
		return capture.RunSanitize(ctx, rest)
	case "probe":
		return runProbe(ctx, rest)
	case "discover":
		return runDiscover(ctx, rest)
	case "serve":
		return runServer(ctx, rest)
	case "version", "--version":
		fmt.Println("selfsight " + version)
		return nil
	case "-h", "--help", "help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "config.yaml", "path to the config file")
	dataDir := fs.String("data", "data", "directory for device config backups")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	// Live per-device status needs the WAX driver (gated on fixtures); the
	// inventory endpoints and the dashboard work today from config alone.
	ui, haveUI := web.Assets()
	if !haveUI {
		ui = nil
		fmt.Fprintln(os.Stderr, "serve: no dashboard embedded (run `npm --prefix web run build`); API still served")
	}
	handler := api.New(cfg, ui, *dataDir)
	handler.EnableReload(*configPath)

	// Convert backups already on disk to the decrypted stored form and seed
	// config change-history from them, so the timeline reaches back to the
	// earliest archive instead of starting empty. Runs in the background
	// (decrypting old archives can take a moment) and is best-effort — it
	// never blocks serving.
	go handler.ConvertAndBackfill()

	// Back up a device whenever its config changes (not on a timer). Changes
	// selfsight makes are already captured by the pre-write backup; this catches
	// changes made directly on the AP.
	go handler.RunBackupWatcher(ctx)
	if cfg.Server.Backups != nil {
		fmt.Fprintln(os.Stderr, "note: server.backups is deprecated and ignored — backups are now taken when a device's config changes")
	}

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Server.Listen, err)
	}

	fmt.Fprintf(os.Stderr, "serve: listening on %s (%d device(s) from %s)\n",
		cfg.Server.Listen, len(cfg.Devices), *configPath)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runProbe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	token := fs.String("token", os.Getenv("SELFSIGHT_WAX_TOKEN"), "warm-session security token (or $SELFSIGHT_WAX_TOKEN)")
	sid := fs.String("lhttpdsid", os.Getenv("SELFSIGHT_WAX_SID"), "warm-session lhttpdsid cookie (or $SELFSIGHT_WAX_SID)")
	user := fs.String("user", os.Getenv("SELFSIGHT_WAX_USER"), "admin username for login (or $SELFSIGHT_WAX_USER)")
	password := fs.String("password", os.Getenv("SELFSIGHT_WAX_PASSWORD"), "admin password for login (or $SELFSIGHT_WAX_PASSWORD)")
	sessionFile := fs.String("session-file", "", "path to persist/reuse the warm session (default: user cache dir)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: selfsight probe <ip> [--user <u> --password <p>]

Logs into one WAX AP, reads its status, and prints JSON. Highest-risk driver
code, kept small and standalone.

Session: probe reuses a saved warm session from the session file if one exists,
so repeated runs don't re-login. Otherwise it logs in with --user/--password (or
$SELFSIGHT_WAX_USER / $SELFSIGHT_WAX_PASSWORD) and persists the session. You can
also inject an existing session with --token/--lhttpdsid.
`)
		fs.PrintDefaults()
	}
	// Parse flags that may appear before or after the <ip> positional (Go's flag
	// package otherwise stops at the first positional).
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) < 1 {
		fs.Usage()
		return errors.New("probe: missing <ip>")
	}
	ip := positional[0]

	sessPath := *sessionFile
	if sessPath == "" {
		p, err := wax.DefaultSessionPath(ip)
		if err != nil {
			return err
		}
		sessPath = p
	}

	// The manager handles it all: reuse the saved cookie, log in with
	// credentials when there is none or it has died, and persist on success.
	var opts []wax.Option
	if pinPath, err := wax.DefaultPinPath(ip); err == nil {
		opts = append(opts, wax.WithPinPath(pinPath))
	}
	mgr := wax.NewManager(ip, sessPath, *user, *password, opts...)
	if *token != "" && *sid != "" {
		mgr.SetSession(*token, *sid) // an explicitly injected session wins
	}

	status, err := mgr.Status(ctx)
	if err != nil {
		if errors.Is(err, wax.ErrManaged) {
			return fmt.Errorf("%w — switch it to standalone mode to use the local API", err)
		}
		return err
	}

	out := struct {
		Device string `json:"device"`
		*wax.Status
	}{Device: ip, Status: status}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func runDiscover(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	concurrency := fs.Int("concurrency", 64, "parallel probes")
	timeout := fs.Duration("timeout", 1500*time.Millisecond, "per-host probe timeout")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: selfsight discover <cidr>

Scans a subnet for NETGEAR WAX access points by fingerprinting the TLS
certificate each device presents (read-only — a handshake, no login). Prints the
candidates as JSON; feed their IPs into config.yaml.

  selfsight discover 192.168.1.0/24
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return errors.New("discover: missing <cidr>")
	}
	found, err := discovery.Sweep(ctx, fs.Arg(0), *concurrency, *timeout)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "discover: found %d WAX AP(s)\n", len(found))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"candidates": found})
}

func usage(w *os.File) {
	fmt.Fprint(w, `selfsight - self-hosted manager for NETGEAR WAX access points

usage:
  selfsight [serve]         run the read-only server + dashboard (--config path)
  selfsight probe <ip>      log into one AP and print its status as JSON
  selfsight discover <cidr> scan a subnet for WAX APs (fingerprint, no login)
  selfsight capture ...     record real AP HTTP exchanges via a proxy (run 'capture -h')
  selfsight import-har ...  turn a DevTools HAR export into raw pairs (run 'import-har -h')
  selfsight sanitize ...    scrub a capture dir into fixtures (run 'sanitize -h')
  selfsight version         print the build version

Docs: README.md (start here), DESIGN.md (protocol + architecture).
`)
}
