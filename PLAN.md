# Plan

Living document — the build approach and where things stand. *What* and
*why* live in [REQUIREMENTS.md](REQUIREMENTS.md); *how it works* lives in
[DESIGN.md](DESIGN.md). Individual tasks are tracked as GitHub issues, not
in this file.

## Approach

**The protocol is the main risk, so it gets retired first.** Real HTTP
exchanges with live hardware are captured, sanitized, and committed as
fixtures before any Go code depends on the behaviour they show. No driver
code is written against an imagined API. When a fixture and a device
disagree, the fixture is re-captured — the code is never patched toward a
guess. See DESIGN.md, "Testing and fixtures".

**Reads ship long before writes.** The read-only dashboard runs as a daily
monitor against a real fleet for a long soak before any write path is
enabled, so the driver meets real-world behaviour — flapping links, renumbered
devices, firmware quirks — while the blast radius is still zero.

**Writes are guarded, never trusted.** Every write is preceded by a fresh
device backup and followed by read-back verification; a device's own
"success" response is never taken as proof. Fleet operations run one device
at a time, never in parallel.

**Anything that touches a live device stays behind an explicit confirmation**
and, during development, a human watching. Config writes, restores, and
firmware upgrades are each drilled against real hardware before being
considered done.

## Status

**Working and proven against live hardware.** Fleet dashboard and per-AP
status; optional drift detection against declared settings; change-triggered
backups with native decryption; restore; readable config history in a local
git store; network discovery and adoption; inventory editing from the UI.

**Built and tested end to end, each behind a typed confirmation.** Guarded
one-off config writes (SSID visibility and state, passphrase, VLAN, security,
radio channel, width, and on/off), restore from a stored snapshot, and
firmware upgrade with live progress. These change live networks, so they are
not enabled by default.

**Also in place.** Optional password auth for the dashboard and API; TLS
certificate pinning on first use; on-demand config reload; a per-device event
log recording reachability changes, identity changes the device reports about
itself, and inventory edits.

**Not started.** Historical charts, alerting, rogue-AP scanning, and any
device class beyond WAX-series access points. See REQUIREMENTS.md for the
full scope boundary.

## Decisions that shaped the design

**The device is the source of truth.** Early designs treated a declared
configuration file as authoritative and pushed it out. That was reversed: an
AP's own configuration is the record, selfsight reads it live, and declaring
settings is optional. Declare nothing and selfsight is a viewer and remote —
nothing is compared, nothing is flagged.

**Backups happen when configuration changes, not on a clock.** A timer
produces either stale snapshots or piles of identical ones. Backups are taken
before any change selfsight makes, when it notices a change made on the device
directly, and on demand. An unchanged configuration is never stored twice.

**Backups are stored decrypted.** The device encrypts its backup with the
admin password, which means a snapshot taken under an old password becomes
unrestorable once the password changes. Snapshots are therefore decoded on
arrival and re-encrypted with the device's *current* password for the trip
back, so any snapshot stays restorable. The conversion is gated by proof: the
decoded form must re-encrypt to the device's exact bytes before the encrypted
original is released.

**Devices are always dialled by address, never by name.** These APs reject
API requests whose `Host:` header carries a DNS name, and their certificates
name no hosts. A name in the config file is resolved per connection and
re-resolved after a transport failure, so a renumbered device heals itself.
Saved sessions are stamped with the host they were minted against and are
discarded rather than replayed if a device entry is re-pointed.

**One experiment was tried and reverted: fleet-wide shared networks** —
declaring a network once and ticking which APs carry it. The mechanism worked
and was verified live; the management model around it did not. Two findings
are worth keeping for whatever replaces it:

- A declared passphrase cannot drift from any status read, because no read
  returns a key. Comparing one needs a separate driver call that returns a
  verdict rather than a value.
- Adopting settings from a device must never invent drift, because drift is
  what a human is later invited to apply.

**Names that become paths are validated where they enter, not where they are
used.** A device name is also a directory name, a file name, and a URL
segment. Checking it at each of those places is a rule nobody remembers on the
next feature, so it is enforced once — at config load, which every hand-edit
and every dashboard edit passes through — and the name is restricted to a
single safe path element.

**Fleet-wide limits are claimed atomically, never checked and then acted on.**
"Only one firmware upgrade at a time, anywhere" cannot be enforced by asking
whether the fleet is idle and starting shortly afterwards: two requests can
both be told yes. The slot is taken in the same step that answers the
question, and handed back if the upgrade does not go on to start.

## Before a public release

The code has been through an independent correctness review and an independent
security review. Both confirmed the guarded-write pipeline, the backup crypto,
certificate pinning, per-device locking and the config-file editing behave as
documented, and found no secrets in the repository. Both also found one real
defect each — the two decisions recorded just above — which are fixed, with
tests that fail against the unfixed code. Request bodies are also now bounded,
and a network scan refuses a range too large to enumerate.

Remaining: one live firmware upgrade with a human watching — the restore,
SSID, and channel drills are done, and the dial-by-address path has run live.
Then tag a first release.
