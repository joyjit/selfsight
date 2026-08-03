# selfsight

**Self-hosted, open-source replacement for NETGEAR Insight** — manage your
NETGEAR access points locally, with no cloud account and no subscription.

> **Status: alpha.** Read-only monitoring works end to end against a live
> WAX610 fleet — dashboard, per-AP status, config drift, backups, and network
> discovery. Guarded config writes and firmware upgrades are built and tested
> but not yet enabled by default. Not yet packaged for general release.

## Why

NETGEAR Insight manages your access points through NETGEAR's cloud, for a
recurring subscription. If the subscription lapses or the cloud service
changes, you lose management of hardware you own. Meanwhile the APs themselves
have a perfectly capable local API — Insight just locks it while a device is
cloud-managed.

selfsight talks to that local API directly. Your APs, your network, your
server — no cloud in the loop.

## What it does

Working today (read-only, proven against live hardware):

- **Dashboard** — fleet overview: online/offline, clients, radios, firmware.
  The AP itself is the source of truth: selfsight reads it live, and keeps the
  last reading on disk so the page paints instantly (and still shows the last
  known picture, with its timestamp, when an AP is unreachable).
- **Drift detection (optional)** — declare the few settings you want enforced
  and selfsight reports where an AP differs and can fix just those fields.
  Declare nothing and selfsight is a pure viewer/remote — nothing is compared,
  nothing is flagged.
- **Backups & restore** — a device is backed up when its configuration
  changes, not on a clock: automatically before any change selfsight makes, and
  on demand. Backups are decrypted natively and stored readable; a restore
  re-encrypts with the device's current admin password, so old snapshots stay
  restorable across password changes (with an explicit confirmation when a
  restore would roll the login password back).
- **Config history** — a readable, diffable record of how every AP's
  configuration changed over time, kept in a local never-pushed git store.
  Ask "what changed on this AP, and when" and get a line-level answer —
  backfilled from existing backups.
- **Discovery** — scan the network and fingerprint your WAX APs, no login,
  then adopt one straight into your inventory from the UI.
- **Inventory management** — add, edit, or remove devices from the dashboard;
  selfsight edits your `config.yaml` for you (one entry at a time, comments
  preserved, previous file backed up first) so you never have to hand-edit YAML
  to onboard an AP. A connection test confirms credentials before you save.

Built and tested end to end (API + dashboard), each action behind a typed
confirmation — they change live networks:

- **Safe writes** — change a setting straight from the dashboard (hide/show or
  enable/disable an SSID, radio channel/on/off) as a one-off write to the AP,
  with nothing recorded anywhere — like the AP's own page, but guarded. If you
  use declared config, the drift view's Apply pushes those fields the same
  way. Every write is preceded by a fresh device backup and followed by
  read-back verification; the device's "success" response is never trusted.
  Fleet operations run one AP at a time, never in parallel.
- **Restore** — upload a saved backup onto a device (reboots the AP; success
  is confirmed by the reboot itself, never assumed).
- **Firmware** — check for and apply updates with live progress (strictly one
  AP at a time; a fresh backup first; the new version is confirmed by a fresh
  login after the reboot).

Also built in: optional **password auth** for the dashboard/API
(`server.auth`), **TLS certificate pinning** (trust-on-first-use) for device
connections, on-demand **config reload**, and **change-triggered backups** (a
fresh archive when the config changes, never on a fixed timer).

## How to run it

One artifact — a single static binary with the web UI embedded, or Docker.

```sh
# monitor your fleet (config.yaml lists your APs + credentials)
selfsight serve --config config.yaml     # dashboard on :8080

# one-off: read a single AP as JSON
selfsight probe 192.0.2.20 --user admin --password ...

# find WAX APs on your network
selfsight discover 192.0.2.0/24
```

```sh
# Docker Compose (recommended)
mkdir -p config data
cp config.example.yaml config/config.yaml   # edit for your APs
cp .env.example .env                         # set the passwords it references
docker compose up -d --build                 # dashboard on :8080
```

Config values can reference `${VARS}` you define in `.env`, so `config.yaml`
stays free of secrets and safe to keep in version control. Runs on bare metal,
a Raspberry Pi, or a NAS. See [config.example.yaml](config.example.yaml) for
the config format and [CONTRIBUTING.md](CONTRIBUTING.md) to hack on it.

## Supported hardware

Developed and validated against a live **WAX610** fleet. Other WAX-series APs
are expected to be similar, but each model needs recorded API fixtures before
it can be claimed as supported — contributions welcome (see
[DESIGN.md](DESIGN.md) for how to capture and sanitize fixtures).

APs must be in **standalone (web-browser managed) mode**. While a device is
Insight-managed, its local configuration API is locked by the vendor.
Switching a WAX AP from Insight to standalone mode preserves its
configuration; see the FAQ in [DESIGN.md](DESIGN.md).

**Coming from Insight?** [MIGRATING.md](MIGRATING.md) is a step-by-step
walkthrough: install selfsight, then move each AP off Insight safely (one at a
time, with a rollback path).

## Project documents

| Doc | What it covers |
|-----|----------------|
| [REQUIREMENTS.md](REQUIREMENTS.md) | Goal, scope, success criteria |
| [PLAN.md](PLAN.md) | Build approach and current status |
| [DESIGN.md](DESIGN.md) | Architecture, protocol notes, examples, FAQ |

All three are living documents and change as the project learns.

## License

[Apache-2.0](LICENSE).

selfsight is an independent project, not affiliated with or endorsed by
NETGEAR. *NETGEAR* and *Insight* are trademarks of NETGEAR, Inc., used here
only to identify the products this software interoperates with.
