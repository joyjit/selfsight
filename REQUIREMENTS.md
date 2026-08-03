# Requirements

Living document — what selfsight must do and why. The build approach and
status live in [PLAN.md](PLAN.md); *how it works* lives in
[DESIGN.md](DESIGN.md).

## Goal

Fully replace NETGEAR Insight for managing WAX-series access points: a
self-hosted server that monitors and configures APs over their local API,
with no cloud dependency and no subscription.

## Who it's for

- The maintainer's own three-AP WAX610 fleet (the reference deployment —
  selfsight must be good enough to run the maintainer's home network).
- Home-lab and small-office users leaving Insight when their subscription
  lapses, who want local control of hardware they own.

## Scope (v1)

| In                                                                                    | Out                                               |
| ------------------------------------------------------------------------------------- | ------------------------------------------------- |
| WAX-series APs in standalone mode                                                     | Insight-managed mode (vendor locks the local API) |
| Monitoring: up/down, clients, radios, system info                                     | NETGEAR switches, routers, other device classes   |
| Config read/write: SSID, security, VLAN, radio                                        | Multi-org / multi-tenant management               |
| One-off config writes from the dashboard (the AP stays the only record of its config) | RADIUS, captive portal                            |
| Optional: declare chosen settings for drift detection and one-click fix               |                                                   |
| Device config backup and restore, taken whenever the config changes                   | Mobile app                                        |
| Firmware check and upgrade                                                            | Historical charts, rogue-AP scan, alerting        |
| Network discovery of APs (may land shortly after v1)                                  | Anything that talks to NETGEAR's cloud            |

Out-of-scope items are candidates for later versions, not rejections —
except cloud dependencies, which are permanently out.
