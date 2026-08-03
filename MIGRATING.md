# Installing selfsight and migrating from NETGEAR Insight

This guide has two parts: **install selfsight**, then **move each access
point off Insight and onto selfsight**. Read it through once before you
start — the order matters, and switching an AP to standalone mode briefly
interrupts that AP's WiFi.

The short version: selfsight can't talk to an AP while Insight still manages
it (the vendor locks the AP's local API in that mode). So migrating means,
for each AP, switching it to **standalone mode** in its own web page and then
adopting it into selfsight.

## Before you start

- **Keep your Insight subscription active until the whole fleet is happily on
  selfsight.** It is your rollback: while an AP is still claimed in your
  Insight account, you can flip it back to Insight and the cloud re-pushes its
  old config. Don't cancel until you're done.
- **Switching to standalone is reversible and keeps your config.** On WAX610
  the switch preserves your SSIDs, VLANs, and admin password, and doesn't
  factory-reset. (Switching *back* to Insight is the direction that wipes and
  re-pushes.)
- **You will need** a machine to run selfsight on — a Linux box, a Raspberry
  Pi, or a NAS — that **can reach your APs over the network**, and your AP admin
  login (the same password you use in Insight). selfsight speaks to each AP's
  local API by its IP address, so it only needs a network route to the APs, not
  the same subnet.

## Part 1 — Install selfsight

You can start with no APs in the config and add them as you migrate.

### Option A — Docker (recommended)

Clone the repo, make the data folders, and start it. The image is built
locally — until a tagged release publishes one, there is nothing to pull.

```
git clone https://github.com/joyjit/selfsight
cd selfsight
mkdir -p config data
```

The repo's own `docker-compose.yml` already covers this. If you would rather
write your own, it needs:

```
services:
  selfsight:
    build: .                   # or a published image, once one exists
    user: "1000:1000"          # uid/gid that owns ./config and ./data
    env_file: .env             # optional: holds any ${VARS} your config uses
    environment:
      - XDG_CACHE_HOME=/data/.cache
    ports:
      - "8080:8080"
    volumes:
      - ./config:/config       # config.yaml lives here
      - ./data:/data           # device backups live here
    restart: unless-stopped
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
```

Put a `config.yaml` in `./config`. You can start almost empty and add your APs
from the dashboard as you migrate them:

```
server:
  listen: ":8080"
  # auth:
  #   password: ${SELFSIGHT_AUTH_PASSWORD}   # optional dashboard password
devices: []
```

Then start it (the first run builds the image, which takes a few minutes):

```
docker compose up -d --build
```

Open `http://<your-server>:8080`. To publish on a different port, change the
left-hand side of the `ports` mapping (for example `"9000:8080"`).

### Option B — standalone binary (no Docker)

selfsight is also a single static binary that serves the same dashboard with no
runtime dependencies — a good fit for a Raspberry Pi or NAS where you'd rather
not run a container.

Download the build for your platform from the releases page (for example
`selfsight-linux-arm64` for a Pi), make it executable, and run it against the
same `config.yaml` shown above:

```
chmod +x selfsight-linux-arm64
./selfsight-linux-arm64 serve --config config.yaml
```

Same dashboard on `:8080`. To keep it running across reboots, install it as a
service (a sample `systemd` unit ships on the releases page).

Whichever option you pick, you don't have to hand-write YAML: selfsight can
add, edit, and remove devices from the dashboard and update `config.yaml` for
you (one entry at a time, your comments preserved, the old file backed up
first).

## Part 2 — Move each AP off Insight

Do this **one AP at a time**. If you run a mesh, migrate a **leaf AP first and
the root / backhaul AP last**, so a reboot can't knock out the APs behind it.

Repeat these four steps for each access point.

### Step 1 — Switch the AP to standalone mode

Open that AP's own web page (type its LAN address into a browser) and log in
with your Insight network password. Find the management-mode setting — on
WAX610 firmware it's under **Management → Configuration → System → Basic**
(the exact menu wording varies by firmware version) — and change it from
**Insight** to **Web-browser (standalone)**.

- On WAX610 this keeps your configuration and does not reboot into defaults.
- **Do not press the hardware Reset button or choose "factory default."** That
  erases the admin password. The mode toggle does not.
- If the AP instead comes back broadcasting a default network (an SSID like
  `NetgearXXXXXX` with passphrase `sharedsecret`), then that firmware reset the
  config during the switch — reconfigure your SSIDs and VLANs from your notes
  before moving on. This isn't seen on WAX610 but is possible on other models.

### Step 2 — Confirm, then back up

Still in the AP's local web page, confirm your SSIDs are intact. Then save a
config backup from the AP's own UI (typically **Management → Maintenance →
Upgrade → Backup and Restore**) as a safety copy. A standalone backup can only
be made *after* the switch, so make one now.

### Step 3 — Adopt the AP into selfsight

In the selfsight dashboard, either:

- **Discover** — scan your LAN, then adopt the AP straight from the results; or
- **Add device** — enter a name, the AP's LAN address, the username (`admin`),
  and the password.

selfsight runs a connection test that confirms the credentials and records the
AP's serial number, pinning that config entry to that physical unit — so
there's nothing to verify by hand. On success it writes the device into
`config.yaml` for you.

### Step 4 — Verify

The AP now appears on the dashboard with live status — clients, radios,
firmware. Take a backup from selfsight itself to confirm the read/write path
end to end. That AP is migrated; move on to the next one.

## Part 3 — Finish leaving Insight

Once every AP is on selfsight and you've watched it run for a while:

- **Remove the APs from your Insight account** (the cloud side). This unclaims
  them so Insight can no longer push config, and lets the subscription lapse.
- **Backups need no setup** — there's no schedule to turn on. selfsight backs
  an AP up whenever its configuration changes: automatically before any change
  it makes itself, and any time you click **Backup now**. Every snapshot is
  also added to the config history, so you can see what changed and when.

## If something goes wrong — rollback

While an AP is **still claimed in your Insight account with an active
subscription**:

- **Flip the AP back to Insight mode.** Open the AP's own web page and go to the
  same management-mode setting you changed in Step 1 (on WAX610, **Management →
  Configuration → System → Basic**). Switch it from **Web-browser (standalone)**
  back to **Insight**. As long as the AP is still claimed in your account and the
  subscription is active, Insight re-applies its stored config a short time after
  the AP reboots — there's a brief window where it broadcasts a default network
  first, then your original settings come back.

This is exactly why you keep the subscription until the migration is finished.

Alternatively, restore from the backup you saved in Step 2 — through the AP's
own web UI, or through selfsight (it reboots the AP and confirms success by the
reboot itself, never by trusting the device's response).

## Quick checklist

```
[ ] selfsight running, dashboard reachable on :8080
[ ] Insight subscription still active (rollback safety)
[ ] For each AP, leaf first / backhaul last:
      [ ] Switched to standalone in the AP's web UI
      [ ] Logged in; SSIDs and VLANs intact
      [ ] Backup saved from the AP's UI
      [ ] Adopted into selfsight (serial pinned)
      [ ] Live status + a selfsight backup verified
[ ] Whole fleet on selfsight and watched for a while
[ ] APs removed from the Insight account; subscription ended
```

---

See [README.md](README.md) for what selfsight does, [DESIGN.md](DESIGN.md) for
the architecture and protocol notes (including the managed-vs-standalone FAQ),
and [REQUIREMENTS.md](REQUIREMENTS.md) for scope. selfsight is an independent
project, not affiliated with or endorsed by NETGEAR.
