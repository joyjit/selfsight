# web/ — React dashboard (read-only)

Vite + TypeScript + TanStack Query + Mantine. The production build is embedded
into the selfsight binary via `go:embed` (see `web/embed.go`).

- `src/api.ts` — typed client for the REST API (`/api/devices`, per-device
  `/api/devices/{name}/status`).
- `src/App.tsx` — fleet grid; each card shows online/Insight-managed/unreachable
  state plus firmware, client count, uptime, and per-radio channel/clients.

## Develop

```
npm install
npm run dev      # proxies /api to a selfsight server on :8080
```

`npm run build` emits `dist/`, which the Go build embeds. CI and the Dockerfile
run the web build before the Go build so a real dashboard ships in the binary.
