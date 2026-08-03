# web/ — React dashboard

Vite + TypeScript + TanStack Query + Mantine. The production build is embedded
into the selfsight binary via `go:embed` (see `web/embed.go`).

- `src/api.ts` — typed client for the REST API (`/api/devices`, per-device
  `/api/devices/{name}/status`).
- `src/App.tsx` — fleet grid; each card shows online/Insight-managed/unreachable
  state plus firmware, client count, uptime, and per-radio channel/clients.

It reads and it writes. Besides the live view, the dashboard adopts a device
(scan the subnet, test the credentials, add it), edits or removes one, pushes
declared config onto a device, makes one-off changes to a network or radio,
deletes a network, takes and restores backups, and starts a firmware upgrade.
Every write goes through the server's guarded pipeline — fresh backup first,
then the write, then a read-back that has to confirm it — and only one access
point is written to at a time.

## Develop

```
npm install
npm run dev      # proxies /api to a selfsight server on :8080
```

`npm run build` emits `dist/`, which the Go build embeds. CI and the Dockerfile
run the web build before the Go build so a real dashboard ships in the binary.
