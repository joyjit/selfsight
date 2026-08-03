# Design

Living document — how selfsight works and why it's built this way. Scope
lives in [REQUIREMENTS.md](REQUIREMENTS.md); approach and status in
[PLAN.md](PLAN.md). This doc is allowed to be verbose; it's where examples,
protocol notes, and the FAQ live.

Protocol details below marked *(observed)* come from live WAX610 hardware.
They are trusted as directionally true, but each one gets re-confirmed by a
recorded transcript before Go code depends on it.

## Design principles

1. **Safety before features.** These APs run real networks. Every write is
   preceded by a fresh backup and followed by read-back verification; fleet
   writes are sequential. A missing feature is annoying; a bricked AP or a
   dropped network is a disaster.
2. **Capture first.** No driver code is written against an imagined API.
   Real device exchanges are recorded, sanitized, committed as fixtures, and
   the code is written to satisfy them. The fixtures double as the only
   public documentation of this protocol.
3. **API first.** Every feature is a documented REST endpoint before it has
   UI. This keeps the server scriptable (curl, cron, integrations) and lets
   the frontend evolve independently.
4. **One artifact.** A single Go binary embeds the built web UI. No
   database, nothing else to install. Docker is a packaging convenience,
   not a requirement.
5. **Boring technology.** Stdlib-leaning Go, mainstream React. Contributors
   should recognize everything.

## Architecture

```
 browser
    │
    ▼
┌─────────────────────────────────────────────┐
│ selfsight (one Go binary)                   │
│                                             │
│  React SPA (static, go:embed)               │
│     │  JSON                                 │
│     ▼                                       │
│  REST API (net/http)                        │
│     │                                       │
│     ▼                                       │
│  core: inventory · desired state · drift    │
│        apply engine · scheduler             │
│     │                        │              │
│     ▼                        ▼              │
│  driver/wax (HTTPS)      /data (plain       │
│     │                    files: backups)    │
└─────┼───────────────────────────────────────┘
      ▼
  WAX access points (local API, standalone mode)

  config.yaml (mounted): inventory + desired config + credentials
```

Two kinds of state, deliberately separated:

- **Desired state** — the user's config file: which APs exist, credentials,
  and what their configuration *should* be. It stays human-owned and
  hand-editable, but selfsight can also edit it for you (add, remove, or
  update a device from the UI) — that is how you adopt a discovered AP or
  change its declared config without opening the file. Those edits touch only
  the one device entry involved, preserving comments and everything else, and
  always leave a timestamped `.bak-*` of the previous file first.
- **Observed state** — what devices actually report. Held in memory and
  re-polled on demand; losing it costs nothing. selfsight writes to disk only
  the config file (via the guarded editor above) and plain files under `/data`
  (device config backups).

Drift is simply the diff between the two.

There is deliberately **no database**: everything selfsight knows is either
re-fetchable from the devices, the user's own config file, or already a
file. If a history/audit feature ever lands, that decision gets revisited —
not before.

### Repository layout

```
selfsight/
├── cmd/selfsight/     main: server, and the `probe` subcommand
├── internal/
│   ├── device/        the vendor boundary: Driver + Codec contracts
│   ├── driver/wax/    session, read, write — the crown jewels
│   ├── core/          inventory, drift, apply engine, scheduler
│   ├── backup/        config history store (generic) + WAX archive crypto
│   └── api/           HTTP handlers
├── web/               React app (Vite); build output embedded
├── testdata/          sanitized device transcripts (see Testing)
├── docs/
├── Dockerfile
└── LICENSE            Apache-2.0
```

`testdata/` is a Go toolchain convention: the compiler ignores it, so
fixtures can never leak into the shipped binary.

### The vendor boundary

selfsight is built so that another brand of access point could be supported
by writing one new driver package — no server, UI, or storage code should
have to change. The boundary is `internal/device`, which defines two
contracts:

- **`device.Driver`** — everything the server does *with* a live device:
  read status, guarded typed writes (apply an SSID, apply radio settings,
  delete a network, set the name — every write takes a fresh backup first
  and is confirmed by read-back inside the driver), backup, restore,
  firmware check and upgrade. All status shapes (`device.Status`, SSIDs,
  clients, firmware, results) are defined here, vendor-neutrally.
- **`device.Codec`** — vendor knowledge that is useful *without* a live
  device: the backup archive format and its crypto (encrypt/decrypt,
  validation, admin-credential fingerprint) and how to flatten an archive
  into the one-setting-per-line config text the history store diffs.

The WAX driver (`internal/driver/wax`) implements both; the server picks the
implementation in exactly one place (`api.Server.newManager`). Protocol
vocabulary — wlan keys, vap slots, write payload shapes — never leaves the
driver package.

Honest limits of the abstraction today: the discovery scan fingerprints are
WAX-specific, the config-history *summarizer* understands the WAX key
vocabulary (unknown vocabularies degrade gracefully to raw diff lines), and
the `probe` CLI subcommand is a WAX debugging tool. Each is contained and
none blocks a second vendor; they generalize when a second vendor actually
exists, not before.

## The WAX driver

Everything selfsight knows about talking to a WAX AP lives in
`internal/driver/wax`, behind a small interface, so future device classes
are new drivers rather than rewrites.

Confirmed against live WAX610 hardware (firmware V12.8.0.7) and the sanitized
transcripts under `testdata/wax610/`:

- **Transport** — HTTPS to the AP's web UI port, self-signed certificate
  (verification off by default for device connections, but pinning is a
  candidate feature). The cert identifies the device: subject `CN=WAX610`,
  `O=Netgear Inc.` — a usable pre-auth discovery fingerprint.
- **Dialed by IP, always.** The API refuses any request whose `Host:` header
  is not a name the device answers to, replying status 1 with a generic
  "Internal error" (`/LogFile` returns an "Invalid request" page). It accepts
  exactly two: the device's **own IP**, and the **FQDN** configured in its LAN
  settings, which is empty out of the box. The match is textual and strict —
  a zero-padded spelling of the same address (`192.0.2.010` for `192.0.2.10`)
  is refused, as is a different case (`AP.EXAMPLE.COM` for `ap.example.com`),
  though a `:443` suffix is tolerated. Ordinary pages are served under any `Host:`, so the
  check lives in the API handler, not the web server config; the shape is
  DNS-rebinding protection, and the vendor UI never trips it because it is
  always reached by IP. Setting an FQDN **adds** a name, it does not replace
  the IP, so the IP is the one address that always works. `host:` in config
  may therefore be a DNS name for the operator's convenience, but the driver
  resolves it and puts the IP in the URL, re-resolving after a transport
  failure so a DHCP renumber heals itself; sessions record the host they were
  minted against and are never replayed against another. The self-signed
  certificate is an independent nuisance for browsers — it carries no Subject
  Alternative Names — but that is a warning to click through, not a refusal,
  and it applies equally to the IP.
- **One API endpoint.** Every read and write is `POST /socketCommunication`
  with a JSON body. A **read** sends the exact config subtree with
  empty-string `""` leaves and the response echoes the shape with values
  filled in; you must name the exact leaves (an empty parent does not dump
  its subtree). The request is all-or-nothing — any unknown key fails the
  whole call.
- **Session** — login establishes two secrets: a **token** and an `lhttpdsid`
  cookie. The login must run inside a lighttpd session the device starts, so the
  driver GETs `/AP_login` first (seeding `lhttpdsid` in a cookie jar), then POSTs
  the credentials (`basicSettings.adminName`/`adminPasswd`) to
  `/socketCommunication` within that jar; the reply returns the token and the
  session is warm. A *cold* credential POST without that GET bootstrap yields a
  session that reads back as locked (status 100) — the bootstrap is required.
  Authenticated calls then send the token raw in a `security:` header with the
  cookie jar `lhttpdsid=…; ssid=base64(token)`, and deliberately **no `time`
  header**: that header selects the device's "Insight-validated" path, which
  answers 100 on a managed AP, whereas the warm-jar path returns real data.
  Login is the one request that does send `time`. No browser is involved.
  Sessions are persisted and reused; login is re-run only when the saved one
  dies. That reuse is not merely an optimization — an AP grants only a small
  fixed number of concurrent login slots (five, observed on V12.8.0.7), and a
  session outlives the device's own ~45-minute bookkeeping by a wide margin.
  selfsight never logs out, so a slot it takes is freed by the device's expiry;
  logging in per call would exhaust the AP. The driver owns this dance; callers
  just say "logged-in client, please".
- **Status codes in the body, not HTTP.** The envelope carries its own
  `status`: `0` = success; `1` = bad/unknown keys in the request; `100` = the
  local API is locked; `401` = the session is dead (re-mint). HTTP 200 means
  nothing by itself. **`100` is ambiguous** and must not be read as
  "Insight-managed" on its own: a dead or displaced session also reads back as
  100, not 401. From a reused session it means "log in again"; only a 100 from
  a freshly minted session means the device is genuinely managed.
- **Write responses lie.** The AP can return success — or a transport
  error/timeout — for a write that did or didn't stick, and wireless writes
  bounce the radio (dropping the response) even on success. The driver never
  reports a write as successful based on the response alone: it re-reads the
  affected config and compares.
- **Mode switching** — flipping a WAX from Insight-managed to standalone
  (local UI: Management → Configuration → System → Basic) preserves the
  device configuration and does not reboot. The reverse direction resets
  config and reboots. selfsight documents this but never performs it; mode
  switching is a deliberate human act.

### The apply path (writes)

Every configuration write, whether from the drift "Apply" button or a future
editor, goes through one pipeline:

```
backup → diff → write → re-read → verify
```

1. **Backup** — take a fresh config backup from the device and store it.
2. **Diff** — compute exactly which fields change; write only those.
3. **Write** — smallest possible change, via the local API.
4. **Re-read** — fetch the affected config back from the device.
5. **Verify** — the change is "applied" only if the re-read shows it.
   Anything else is reported as a failure with both values shown.

Fleet-wide operations (apply to all, firmware upgrades) run **strictly
sequentially**. An AP mid-write or mid-upgrade can drop its clients; doing
that to every AP at once takes down the whole network, including possibly
the connection driving the upgrade.

**What is writable** tracks exactly what the protocol work proved end to end,
nothing more: the AP name; the SSID core block (name, security, passphrase,
VLAN, hidden, enabled) — edited in place, created in a free slot, or deleted
by slot (`DELETE /api/devices/{name}/ssids/{ssid}`, refused for the primary
SSID and for SSIDs still declared in desired config); and per-band radio
channel and on/off. Radio transmit power, channel width, and operate mode are
deliberately **not** writable yet: their device value codes are unmapped, and
selfsight never writes values whose semantics aren't proven. SSID delete is
the one imperative write (an SSID absent from desired config is unmanaged,
not deleted); everything else is declarative via drift + Apply.

### Backups and restore

Backup and restore ride the AP's own mechanism (endpoints confirmed against
live hardware; found in the AP's static JS, not guessed):

- **Backup (read-only):** `POST /LogFile` with `{"method": 3, "password":
  "<admin password>"}` — warm-jar signed; the AP re-confirms the admin
  password before releasing a backup — then `GET /wac510-backup` for the
  archive. The filename arrives in `Content-Disposition` (the AP names it by
  model/AP-name/firmware/date). The archive is encrypted by the AP, but the
  format is now understood and selfsight can decrypt it natively (see "Backup
  decryption and config history" below) — so backups are both restore targets
  *and* a readable record of past configuration.
- **Backups happen on change, not on a clock.** A device is backed up when its
  configuration actually changes: automatically before any write selfsight
  makes (the hard rule — a fresh backup precedes every write), when selfsight
  notices the config has changed since the last backup (including a change made
  directly on the AP's own web UI), and on demand. There is no time-based
  scheduler: a clock-driven backup of an unchanged config only produces a
  redundant snapshot — a wasted AP login, a duplicate archive on disk, history
  churn — with nothing to record. Backups still visit devices one at a time (no
  fleet operation ever runs parallel) and prefix each archive with a UTC
  timestamp (the device's own filename has only day granularity, so same-day
  snapshots would otherwise overwrite). Implemented by `RunBackupWatcher`: an
  initial check shortly after startup (so a change made while selfsight was
  down is caught promptly), then a routine check on an interval, keeping a
  pull only when it differs from the newest stored backup
  (`backup.StableConfig`-normalized). Both timings are configurable
  (`server.backupCheck.startupDelay` / `interval`, defaulting to 2m / 6h);
  these are *check* timings, not a backup schedule — an unchanged config is
  never stored.
- **Restore (DISRUPTIVE — reboots the AP):** `POST /restoreSettings` as
  `multipart/form-data`, file field `file`, warm-jar signed **plus the admin
  password in a `password` header** (a header, not a body field) — the AP
  decrypts the upload with that header password. The AP accepts exactly one
  `.tar` of at most 2 MB, and rejects an archive without `tmp/decryptedKeys`
  inside. A restore reboots the device and drops **every** connected WiFi
  client — a far larger blast radius than a config write.
- **What selfsight does around a restore.** Snapshots are stored decrypted,
  so the server re-encrypts the chosen snapshot **with the current admin
  password** just before upload — any snapshot stays restorable no matter
  what the password was when it was taken. Before the write it takes a fresh
  backup (hard rule), which doubles as the reference for the password check
  below.
- **Restores can roll the login password back.** A backup carries the AP's
  login-password file (`sysconfig/shadow`), and the AP's own restore script
  deletes the current one and copies the backup's in. So restoring a snapshot
  taken under a different admin password reverts the AP to that old password
  after the reboot. To spot this, selfsight compares the **admin login stored
  in the config** — `basicSettings.adminName` plus the `adminPasswd` hash —
  between the snapshot and the fresh pre-restore backup, and refuses the
  restore (409, `passwordReverts: true`) until the caller resends with
  `acceptPasswordRevert: true`. (It does *not* compare `sysconfig/shadow`
  directly: the device re-salts that file on every reboot, so two backups of
  the same password never match there, which would warn on almost every
  restore. The `adminPasswd` hash, by contrast, is byte-stable across reboots
  and changes only when the password actually changes.) The dashboard turns
  the refusal into an explicit second confirmation. After such a restore the
  password selfsight is configured with must be updated to the old one.
- **Restore verification is the session-reset check.** The AP's response
  status is untrustworthy here (a live test saw a restore succeed while the
  response said otherwise), and plain reachability proves nothing — a
  rejected upload leaves the AP up throughout, indistinguishable from a fast
  reboot. What a reboot *does* do is kill every session on the device. So:
  if the pre-restore session stops authenticating, the device rebooted and
  the restore took; if that session still works after the wait, the restore
  did not take. That is the only success signal selfsight uses.

## Backup decryption and config history

The AP encrypts its config backup, but only to protect it in transit/at rest —
the key is the **device admin password**, which selfsight already holds. The
format was reverse-engineered from the firmware's own `file_enc` (libgcrypt); a
native Go decryptor (`internal/backup`) was verified byte-for-byte against the
vendor binary across every available real backup, so no vendor binary or
emulator is needed at runtime. Format:

```
[ salt: 128 ][ IV: 16 ][ ciphertext: AES-256-CBC ][ HMAC-SHA512: 64 ]
derived = PBKDF2-HMAC-SHA512(adminPassword, salt, iter=10000, dkLen=96)
aesKey  = derived[0:32]      macKey = derived[32:96]
HMAC-SHA512(macKey, salt||IV||ciphertext) == trailing 64 bytes  (authenticated)
```

The plaintext is a tar holding the device's `/sysconfig/config` — a flat
`key value` line-per-setting file (the *full* config, hundreds of lines,
versus the handful the live read parses) — plus `sysconfig/shadow` (the login
password hashes), `tmp/decryptedKeys` (the AP's own validity marker), and a
few optional database files. A wrong password fails the HMAC check before any
bytes are produced.

**Backups are stored decrypted.** The decoded snapshot is the source of truth;
encryption is only put back on for the trip to the AP (see the restore notes
above). The conversion is gated by proof: the plaintext is re-encrypted with
the archive's own salt/IV and must reproduce the AP's bytes exactly
(`backup.VerifyRoundTrip`) before the encrypted form is let go — a snapshot
that passes can always be turned back into a valid archive. This removes the
old trap where an archive could only ever be decrypted with the admin password
in force when it was taken. An archive that fails the check (taken under a
password we no longer have) is kept encrypted as-is and logged. On startup the
server converts archives already on disk (`ConvertAndBackfill`).

**Config history.** Because the config is line-oriented, changes over time are
just line diffs. Every backup — the automatic pre-write backup every
apply/change/restore/upgrade takes, each change selfsight detects, and manual
ones — commits the config to a local git store (`<dataDir>/history`, one file
per device). Endpoints:
`GET …/history` lists snapshots; `GET …/history/diff?from=&to=` returns the
change between two. Startup backfill reaches back to the oldest archive on
disk.

**History is stored in full — by explicit decision.** A history that dropped
data cannot serve as an audit trail, and both the store and the backups are
the operator's own local record on their own box. That makes the rule
absolute: the history repo and the backup directory must **never be given a
remote, pushed, or copied off the box** (`data/` is git-ignored). A redaction
pass (`backup.Redact`, key-name blocklist with SHA-256 fingerprints) is kept
in the code for the day a shareable export is wanted.

**One normalization — encrypted-at-rest secrets.** The config never holds a
readable password: every credential (WiFi pre-shared keys, RADIUS/WDS/802.1x
shared secrets, radSec keys) is stored as an opaque AES-wrapped hex blob. The
AP **re-wraps these on every reboot** — same plaintext, fresh ciphertext — so
their stored value changes on every restart even when nothing really changed,
and a restore (which reboots) would otherwise show ~170 phantom "changes."
Since the ciphertext of a real change is indistinguishable from a re-wrap,
`backup.StableConfig` replaces every such blob (detected by shape — a 64+ hex
value) with a fixed `«encrypted»` placeholder in the history view *only*
(backups keep the real bytes for restore). The key stays, so a secret field
appearing or disappearing still shows; only the meaningless
ciphertext-vs-ciphertext diff is dropped. The audit signal — SSIDs, VLANs,
radios, hidden flags, names — is fully preserved. This is a display
normalization, not redaction: nothing readable was ever there to hide.

## Configuration model

The access point itself is the sole record of its own configuration.
selfsight never keeps a competing copy: the dashboard reads the AP live
(caching the last reading on disk purely for instant display), changes made
from the UI are one-off writes to the AP (`POST …/change`, nothing recorded),
and disaster recovery is the stored backup snapshots. The `desired:` block
below is **optional** — declare a field and selfsight will check it and offer
to fix it (drift); declare nothing and nothing is ever compared or flagged.

One YAML file, mounted into the container (or passed by path), owns
inventory and — only if you opt in — declared settings. Sketch — the real
schema will grow as features land:

```yaml
server:
  listen: ":8080"
  # No backup schedule: selfsight backs a device up when its config changes
  # (before any change it makes, and when it detects one) and on demand. The
  # optional backupCheck block only tunes the out-of-band check cadence.
  backupCheck:
    startupDelay: 2m    # first check after startup (default)
    interval: 6h        # routine check cadence (default; minimum 1m)

devices:
  - name: living-room
    host: 192.0.2.20
    model: WAX610
    username: admin
    password: "s3cret"        # see Security
    desired:
      ssids:
        - name: HomeNet
          vlan: 1
          security: wpa2-psk
          passphrase: "also-s3cret"
      radios:
        2g: { channel: auto, power: full }
        5g: { channel: 44,   power: full }
```

Rules:

- Unknown/omitted fields are simply not managed — selfsight only diffs and
  writes what the user declared. Start small, adopt gradually (or never).
- One-off UI changes and declarations must not fight: `POST …/change` refuses
  a field that is declared for that device (409) — the next apply would
  silently revert it. Change or remove the declaration instead.
- The last successful status reading per device is persisted to
  `<dataDir>/status/<device>.json` and served by
  `GET …/status/cached` (with its timestamp) so the dashboard paints
  instantly and stays informative when an AP is down. Display only — it is
  never compared against anything, and every successful read overwrites it.
  A device rename moves the file, like the backup directory.
- Any value may reference an environment variable as `${VAR}`, expanded when
  the config loads (an unset reference fails loudly at startup). This keeps
  secrets — device passwords, the UI auth password — out of the file, so the
  file can be committed to a deploy repo with the real values in a `.env` / the
  process environment. Expansion is load-only: the UI write path edits the raw
  file text, so a `${VAR}` in an untouched device is preserved verbatim.
- The file is read at startup and on demand (reload endpoint). selfsight
  can also write it — adding, removing, or updating a device from the UI
  (`POST/PUT/DELETE /api/devices…`). Each write edits only the one device
  entry (comments, key order, and the other devices are preserved), validates
  the result before saving, and writes a timestamped `.bak-*` of the previous
  file first. Hand-editing the file still works; the write path is additive,
  not a replacement.

## Testing and fixtures

The test strategy has to work for a project whose target hardware most
contributors don't own.

**Capture → sanitize → commit:**

1. **Capture** real request/response exchanges against a live AP with a
   small capture tool (one of the project's first deliverables).
2. **Sanitize** — a scripted pass (not manual editing) replaces MACs,
   serials, SSIDs, IPs, hostnames, and any credential material with
   plausible fakes, preserving structure byte-for-byte. Raw captures live
   outside this repository and are never committed — git history is
   permanent, so sanitization happens *before* the repo, not after.
3. **Commit** the sanitized transcript under `testdata/wax610/`, e.g.:

```
testdata/wax610/
├── login/            request + response pairs
├── status.json
├── clients.json
├── config-read.json
└── managed-mode-status-100.json
```

Example of what a sanitized fixture looks like (values fake, shape real):

```json
{
  "status": 0,
  "clientList": [
    {
      "mac": "AA:BB:CC:00:11:22",
      "ip": "192.0.2.10",
      "ssid": "ExampleNet",
      "band": "5G",
      "rssi": -52
    }
  ]
}
```

Driver tests replay these through an in-process fake AP (an `httptest`
server) and assert the driver parses responses correctly and sends
correctly-shaped requests. Fast, deterministic, runs anywhere — CI never
touches hardware.

Precedents for this pattern: `unpoller/unifi` (Go client for UniFi's
undocumented API, tests parse sanitized real captures) and Home Assistant's
per-integration fixtures directories (captured device responses, values
genericized).

**Contributing fixtures for a new model:** run the capture tool against
your AP, run the sanitizer, eyeball the output, open a PR with the
sanitized files only. This is the main way new hardware gets supported.

## Discovery (planned)

Tiered, cheapest first:

1. **Active subnet sweep** — probe candidate hosts' HTTPS port and
   fingerprint NETGEAR APs from pre-auth signals (TLS certificate fields,
   login page, MAC OUI where ARP is visible). Feeds candidates into the
   normal add-device API flow: found → user supplies credentials → added.
2. **Passive listening** (mDNS/SSDP/LLDP) — only if the sweep proves
   insufficient; whether WAX APs announce anything useful is an open
   question for a capture session.

Docker caveat: TCP sweeps work from a bridge network, but ARP and
multicast do not cross the bridge. Full discovery needs
`network_mode: host` (documented), or users add devices by IP.

## Deployment

Reference deployment is Docker Compose; the same binary runs bare on any
Linux/arm64/amd64 box.

```yaml
services:
  selfsight:
    image: selfsight/selfsight
    ports: ["8080:8080"]
    volumes:
      - ./config:/config
      - selfsight-data:/data
    restart: unless-stopped
volumes:
  selfsight-data:
```

`/config` holds the user's YAML; `/data` is where selfsight writes device
config backups (plain files), so they outlive the container. Deployment
automation for the maintainer's own server lives in a separate private
repository, as it contains real credentials.

## Security

- **Device credentials** are plaintext in the mounted config file. This is
  the standard home-lab trade-off (compare Home Assistant's YAML era,
  Prometheus scrape configs): the file lives on a server the user already
  controls; at-rest encryption would protect against an attacker who has
  already won. Documented clearly: protect the file, `chmod 600`.
- **No secrets in this repo** — enforced by the sanitizer for fixtures and
  by review for everything else. Real IPs/SSIDs/serials count as secrets
  here.
- **UI/API auth** — optional password auth (`server.auth.password`) gates
  every API route except health and the login endpoints; the SPA stays open
  so it can render the login form. Sessions are random in-memory tokens in an
  HttpOnly cookie (24 h sliding); a server restart logs everyone out. Failed
  logins are delayed to damp brute force. With no `auth` block the server is
  open — the original trusted-LAN default, and it logs a loud warning saying
  so — but **enable auth before enabling writes**: the write endpoints act on
  your network. Exposing selfsight beyond the LAN still wants a reverse proxy
  with TLS in front; behind one, the session cookie is marked `Secure`
  (detected via `X-Forwarded-Proto`).
- **Serial pinning** — each device entry can record the unit's serial number
  (`serial:`, captured automatically by the UI's connection test on adopt).
  Every write-class operation (apply, restore, firmware upgrade, name change)
  first compares it against the live device and refuses on mismatch — so a
  host that now points at different hardware (DHCP reshuffle, replaced unit)
  never receives another entry's config. Backups also contain WiFi passphrases:
  treat the data directory as sensitive.
- **Device TLS** — AP certificates are self-signed, so classic verification
  is impossible; the driver instead **pins each device's certificate on
  first use** (SHA-256 of the leaf, stored next to the saved session). A
  later mismatch fails the connection with an error naming the pin file —
  delete it to re-trust after a legitimate cert change (e.g. factory reset).

## FAQ

**Is this affiliated with NETGEAR?**
No. Independent project; no NETGEAR code, firmware, or cloud APIs are used.
It speaks to the local web API that ships on the devices you bought.

**Will it work while my APs are Insight-managed?**
No, and it can't: while a device is Insight-managed, the vendor locks the
local configuration API (it answers with status 100). You must switch each
AP to standalone mode first. On WAX610 this switch preserves the device's
configuration and doesn't reboot *(observed; switching back to Insight is
the direction that resets config)*. Do it from the AP's local web UI;
selfsight deliberately doesn't automate mode switching.

**Why Go and React?**
Go compiles the whole server — web UI included — into one static binary
that runs anywhere, with no runtime dependencies to install. React keeps
the UI in the most widely known frontend ecosystem, which matters for
contributors. Both are deliberately boring choices.

**Why not just use each AP's web UI?**
That works for one AP. selfsight exists for fleet concerns: one dashboard,
declared config with drift detection, automatic backups when the config
changes, sequential firmware rollouts — the things Insight actually did for
you.

**Can selfsight brick my AP?**
The design treats this as the primary risk: writes only through the
backup → diff → write → verify pipeline, minimal diffs only, sequential
fleet operations, and restore-from-backup as the recovery path. Firmware
flashing is inherently the riskiest operation anywhere; selfsight uses the
device's own upgrade mechanism and never fleet-parallelizes it.

**Which models are supported?**
WAX610 is the validated reference (the maintainer's production fleet).
Other WAX models likely share most of the API but are unclaimed until
someone contributes sanitized fixtures from real hardware. Switches and
routers are a different protocol family — out of scope for v1, possible as
future drivers.
