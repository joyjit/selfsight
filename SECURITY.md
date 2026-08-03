# Security

## Reporting a problem

Please report security problems **privately**, not as a public issue.

Use GitHub's private vulnerability reporting on this repository: open the
**Security** tab and choose **Report a vulnerability**. That opens a private
advisory visible only to the maintainer.

Include what you need to explain the problem and nothing more. In particular,
**do not paste real IP addresses, SSIDs, MAC addresses, serial numbers, device
passwords, or backup archives** — a redacted example or a description of the
shape of the data is enough, and this repository never accepts real values,
including in issues and pull requests.

Expect an acknowledgement within a week. There is no bounty; this is a
single-maintainer project.

## What selfsight is, and what it holds

selfsight is a self-hosted dashboard for access points on your own network. To
do its job it necessarily holds things worth protecting:

- **Device admin passwords**, in the config file it reads (or in the
  environment the file's `${VAR}` references come from).
- **Device backups**, under the data directory. These are full configuration
  archives and they contain your WiFi passphrases.
- **A warm session and a certificate pin per device**, in a cache directory.

Everything on that list is a plain file on the machine you run this on. That
is a deliberate choice, and it comes with conditions.

## Running it safely

**Require a login.** Set `server.auth.password` (the shipped example config
does, reading `SELFSIGHT_AUTH_PASSWORD` from your `.env`). Without it, anyone
who can reach the port can read your credentials' effects and reconfigure your
access points. The server prints a loud warning when auth is off.

**Bind it to localhost.** The reference `docker-compose.yml` publishes on
`127.0.0.1` for this reason. To reach it from elsewhere, put a reverse proxy
with TLS in front rather than opening the port — selfsight speaks plain HTTP,
so on an open port the login password and the session cookie cross the network
in the clear.

**Protect the files.** `chmod 600` the config file, and treat the data
directory as sensitive: it holds the backups, and the backups hold your WiFi
passphrases.

**Keep the secrets out of the config file if you can.** Any value may be
written as `${VAR}` and filled in from the environment, so the config file
itself can stay free of secrets and safe to keep in version control. Editing a
device from the dashboard preserves the reference rather than expanding it.

## Accepted risks

These are known and deliberate, not oversights:

- **Backups are stored decrypted** (mode 0600). The device encrypts an archive
  with its own admin password; selfsight decrypts it on arrival so the archive
  can be inspected, diffed, and restored even after that password changes.
  Encrypting them again locally would put the key on the same disk as the
  data, which buys very little. The mitigation is the machine and the file
  permissions, not local crypto.
- **The config change history is plaintext, but carries no readable secret.**
  Every secret-bearing field is stored as a short hash of its value, so a
  changed passphrase shows up as a change without the passphrase being
  written down anywhere.
- **Credentials in the config file are plaintext.** Same trade-off as most
  self-hosted tools: the file lives on a server you already control, and
  at-rest encryption mainly protects against an attacker who has already won.

## What is defended against

- **Someone else's website using your logged-in session.** A request that
  changes something must be JSON or carry a custom header, and its `Origin`
  must match this server — none of which another site's page can arrange.
- **Password guessing.** Wrong passwords are counted per source address, which
  is locked out after five failures in five minutes. The comparison itself is
  constant-time.
- **Being used to reach somewhere else.** A device address must be a plain IP
  or host name; the network sweep only accepts private, loopback and
  link-local ranges.
- **An impostor device.** Access point certificates are self-signed, so the
  driver records each device's certificate the first time it connects and
  refuses a later connection presenting a different one, naming the file to
  delete if the device legitimately re-keyed.
- **Writing to the wrong unit.** A device entry can record the hardware's
  serial number, which is checked against the live device before every write.

## Supported versions

The most recent release, and `main`. There are no backports.
