# testdata/wax610 — sanitized WAX610 transcripts

The **only public documentation of the WAX610 local API** and the fixtures every
driver test replays. The Go toolchain ignores `testdata/`, so nothing here ships
in the binary.

## Hard rules

- **Sanitized only.** Real MACs, serials, SSIDs, IPs, hostnames, and any
  credential material are secrets (see `AGENTS.md`). Raw captures never enter
  this repo — git history is permanent.
- **Scripted, then eyeballed.** Files are produced by `selfsight sanitize`, then
  a human reviews every one before commit (YELLOW tier).

## How these were produced

Captured from a live WAX610 (firmware V12.8.0.7) via the browser Network log,
converted with `selfsight import-har`, and scrubbed with `selfsight sanitize`
using a boundary-aware replacement map. Sanitized values: serial → `SERIAL…`,
MAC OUI → `AA:BB:CC:*` (last 3 octets kept), private IP → `192.0.2.*`, real
SSIDs → `example.com`-based names, `presharedKey` → `REDACTED-KEY-*`, AP name →
`LivingRoomAP`. Protocol vocabulary (e.g. `Management (allow)`, `Guest (deny)`,
`iOS`, `11ax`) is preserved verbatim — it is not secret.

`basicSettings.fqdn` in `system-info` came from a later capture on the same
firmware, against an AP with an FQDN configured, sanitized to
`livingroomap.example.com`. An AP with none returns the literal string `"0"`,
which the driver maps to empty — that sentinel is covered by a unit test rather
than a second fixture.

## The protocol (one endpoint)

All reads are `POST /socketCommunication` with a warm-jar session (see DESIGN.md,
"The WAX driver"). A **read** sends the exact config subtree with empty-string
`""` leaves; the response echoes the shape with values filled in. The envelope
carries `status`: `0`=ok, `1`=bad/unknown keys, `100`=Insight-managed (local API
locked), `401`=auth expired.

## Fixtures (each is a request payload + its response)

| Fixture | Reads |
|---------|-------|
| `apname` | `basicSettings.apName`, productId, PoE source |
| `system-info` | serial, ethernet MAC, firmware, IP/gateway, uptime, radio station counts, traffic, channel util, `fqdn` |
| `radios` | per-band `radioStatus`, `maxWirelessClients` |
| `clients-detail` | `optCliList` per radio: connected stations (`ip`, `mac`, hostname, `ssid`, OS, mode, VLAN). Standalone-only; managed APs return status 100 |
| `ssid-details` | `ssidGetDetails`: SSID, auth/encryption, `presharedKey`, VLAN, access-control groups (the full per-VAP config-read) |
| `clients` | per-SSID connected-client counts (`clientList`) |
| `firmware` | `FwUpdate`: image-available, version, last-checked, release-notes URL |
| `ssid-delete` | **write**: `ssidDelete` removes an SSID slot (`{"ssidDelete":{"SSID2":""}}` → `{"status":0}`); the slot returns to `ssidGetFree`. Transcribed from a live-proven exchange rather than a browser HAR |

Each `*.request.json` is the payload to POST; each `*.response.json` is the
sanitized device reply. Driver tests replay these through an in-process fake AP.

## Not yet captured

- **Login / session pair** — the login posts to `/AP_login` before the recording
  started; the session mechanics (token + `lhttpdsid`, `ssid=base64(token)`
  cookie, `security` header) are documented in DESIGN.md and to be captured/added.
- **`managed-mode-status-100`** — needs an Insight-managed AP; this fleet is
  standalone, so `status 100` can't be produced from it. To be contributed
  separately or synthesized from the documented shape.
- **`optCliList`** (per-client MAC/hostname list) and **`ssidGetFree`** — the
  captured UI session used the count-only `clientList`; a follow-up capture can
  add the detailed client list.
