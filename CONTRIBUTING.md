# Contributing to selfsight

Thanks for helping. selfsight manages NETGEAR WAX access points over their local
API, with no cloud and no subscription. It's a Go binary with an embedded React
dashboard. This guide covers the dev loop, the testing model, and the safety
rules that are non-negotiable because this software writes to live networks.

## Development setup

You need Go 1.22+ and Node 20+.

```
# build the dashboard (embedded into the binary via go:embed)
npm --prefix web install
npm --prefix web run build

# build and test the server
go build ./...
go test ./...
```

`npm --prefix web run dev` runs the dashboard with hot reload, proxying `/api`
to a `selfsight serve` on `:8080`.

## Project layout

```
cmd/selfsight/      main + subcommands (serve, probe, discover, capture, sanitize)
internal/driver/wax the WAX driver: session, reads, guarded writes, backup, firmware
internal/core       config loading, drift — device-independent
internal/api        REST handlers
internal/discovery  subnet fingerprint scan
web/                React dashboard (Vite)
testdata/wax610/    sanitized device transcripts — the protocol spec + test fixtures
```

## The testing model: sanitized fixtures

selfsight is tested against **sanitized real device transcripts**, so CI never
touches hardware and contributors don't need an AP to work on most of the code.
Driver tests replay `testdata/wax610/` through an in-process fake AP.

**No driver code is written against an imagined API** — every behavior is backed
by a captured transcript. If you're adding a read or write, capture it first.

## Supporting new hardware (contributing fixtures)

The main way new models get supported is contributing sanitized fixtures:

1. Record real exchanges from your AP's web UI. The easiest path: open your
   browser's DevTools → Network, drive the AP's UI, and "Save all as HAR".
2. Convert and scrub — **raw captures contain secrets and must never be
   committed**:
   
   ```
   selfsight import-har --in capture.har --host <ap-ip> --out /tmp/raw
   cp testdata/wax610/map.example.yaml map.yaml   # fill in your real values
   selfsight sanitize --in /tmp/raw --out testdata/<model>/ --map map.yaml
   ```
3. **Eyeball every output file** — no real MACs, serials, SSIDs, IPs, hostnames,
   or credentials. MACs and private IPs are scrubbed automatically; names are
   not.
4. Open a PR with the sanitized files only.

## Safety rules

These protect real networks and are enforced in code and review:

- **Every configuration write is preceded by a fresh backup** and followed by
  read-back verification. A write is never reported successful on the device's
  response alone — the API lies (and wireless writes bounce the radio).
- **Fleet writes and firmware upgrades are strictly sequential**, never parallel
  — doing a disruptive op to every AP at once can take down the whole network.
- **No secrets in the repository, ever** — including fixtures and git history.
  Real IPs, SSIDs, MACs, and serials count as secrets.

## Pull requests

- Run `gofmt`, `go vet ./...`, `go test ./...`, and `npm --prefix web run build`
  before pushing; CI runs all of these.
- Keep changes focused. Match the surrounding code's style.
- Changes to the driver's write/apply path, the sanitizer, or committed fixtures
  get extra review — git history is permanent and these touch live hardware.
