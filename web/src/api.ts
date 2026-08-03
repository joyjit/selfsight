// Provisional API contract for the read-only dashboard.
//
// /api/devices lists inventory loaded from config.yaml (no credentials). It is
// live now: it needs only the config loader, not the WAX driver.
//
// Per-device live status (clients, radios, firmware, up/down) is served by the
// driver read path and is not wired yet; the server
// returns 501 for it today. The Device shape below will grow a `status` object
// once that lands — kept deliberately small so it tracks real fixtures, not a
// guess.

export interface Device {
  name: string;
  host: string;
  model: string;
}

export interface DevicesResponse {
  devices: Device[];
}

// The dashboard's session lives server-side in memory, so a server restart
// (e.g. a redeploy) silently kills it while the tab keeps showing cached data.
// Every API helper below routes through apiFetch, which reports a 401 (other
// than from the auth endpoints themselves) so the app can drop back to the
// login screen instead of failing every action with an invisible error.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

// The server refuses a request that changes something unless it carries this
// header — a browser will not attach a custom header to a form post or any
// other request a different site can make on the user's behalf, so it proves
// the request came from here. Set on every request, not just the write ones,
// so a route that later becomes a write cannot be forgotten.
async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  headers.set("X-Requested-With", "selfsight");
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    onUnauthorized?.();
  }
  return res;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await apiFetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    let msg = `${path}: ${res.status} ${res.statusText}`;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* keep default */
    }
    throw new StatusError(msg, res.status);
  }
  return (await res.json()) as T;
}

export function fetchDevices(): Promise<DevicesResponse> {
  return getJSON<DevicesResponse>("/api/devices");
}

// Live per-device status from GET /api/devices/{name}/status. Shapes mirror the
// Go driver's JSON (internal/driver/wax). All sub-sections but `system` are
// best-effort and may be absent.
export interface DeviceStatus {
  system: {
    name: string;
    serial: string;
    mac: string;
    firmware: string;
    ip: string;
    gateway: string;
    gatewayUp: boolean;
    uptime: string;
    standalone: boolean;
    devices: number;
    // The name the AP answers to besides its IP; absent when none is set.
    fqdn?: string;
    radios: Radio[];
  };
  ssids?: Ssid[];
  clients?: { total: number; perSSID?: SsidCount[] };
  clientList?: ClientDetail[];
  radioSettings?: RadioSetting[];
  firmware?: {
    updateAvailable: boolean;
    availableImage: string;
    lastChecked?: string;
    releaseNotesURL?: string;
  };
}

export interface Radio {
  band: string;
  mode: string;
  channel: string;
  channelWidth: string;
  stations: number;
  traffic?: string;
  channelUtil?: string;
  // Airtime split: selfUtil is our own networks' share, obssUtil is other
  // (neighbour) networks — the outside-interference signal.
  selfUtil?: string;
  obssUtil?: string;
}

// Per-band on/off + client cap (from wlanSettingTable).
export interface RadioSetting {
  band: string;
  on: boolean;
  maxClients: number;
}

// One SSID's client count on one band.
export interface SsidCount {
  ssid: string;
  band: string;
  count: number;
}

// One connected station (from optCliList). No signal/rate — the AP doesn't
// expose those in this table.
export interface ClientDetail {
  hostname: string;
  mac: string;
  ip: string;
  ssid: string;
  band: string;
  os: string;
  mode: string;
  vlan: number;
}

export interface Ssid {
  name: string;
  vlan: number;
  security: string;
  hidden: boolean;
  enabled: boolean;
  bands: string[];
}

// StatusError carries the HTTP status so the UI can distinguish an
// Insight-managed device (409) from an unreachable one.
export class StatusError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number,
  ) {
    super(message);
  }
}

export interface DriftItem {
  scope: string;
  field: string;
  desired: string;
  observed: string;
  inSync: boolean;
}

export interface DriftReport {
  inSync: boolean;
  items: DriftItem[];
}

export function fetchDeviceDrift(name: string): Promise<DriftReport> {
  return getJSON<DriftReport>(`/api/devices/${encodeURIComponent(name)}/drift`);
}

export interface BackupEntry {
  file: string;
  size: number;
  modified: string;
}

export interface BackupsResponse {
  device: string;
  backups: BackupEntry[];
}

export function fetchDeviceBackups(name: string): Promise<BackupsResponse> {
  return getJSON<BackupsResponse>(
    `/api/devices/${encodeURIComponent(name)}/backups`,
  );
}

async function postJSON<T>(path: string): Promise<T> {
  const res = await apiFetch(path, {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body as T;
}

// Takes a fresh backup on the device (read-only there) and stores it on the
// server. Returns the stored file path.
export function takeDeviceBackup(name: string): Promise<{ backup: string }> {
  return postJSON<{ backup: string }>(
    `/api/devices/${encodeURIComponent(name)}/backup`,
  );
}

// Re-reads config.yaml on the server; the UI refetches everything after.
export function reloadConfig(): Promise<{ devices: number }> {
  return postJSON<{ devices: number }>("/api/config/reload");
}

// Drift apply: pushes declared config onto the device (guarded writes).
export interface ApplyResult {
  change: string;
  backup: string;
  applied: boolean;
  observed: string;
}

export interface ApplyResponse {
  device: string;
  results: ApplyResult[];
  skipped?: string[];
  error?: string;
}

export async function applyDevice(name: string): Promise<ApplyResponse> {
  const res = await apiFetch(`/api/devices/${encodeURIComponent(name)}/apply`, {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  const body = (await res.json().catch(() => ({}))) as ApplyResponse;
  if (!res.ok && res.status !== 409) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body;
}

// Firmware: deliberate cloud check, and the (very disruptive) upgrade.
export interface FirmwareInfo {
  updateAvailable: boolean;
  availableImage: string;
  lastChecked: string;
}

export function checkFirmware(name: string): Promise<FirmwareInfo> {
  return postJSON<FirmwareInfo>(
    `/api/devices/${encodeURIComponent(name)}/firmware/check`,
  );
}

export function startUpgrade(name: string): Promise<{ started: boolean }> {
  return postJSON<{ started: boolean }>(
    `/api/devices/${encodeURIComponent(name)}/firmware/upgrade`,
  );
}

export interface UpgradeProgress {
  running: boolean;
  phase?: string;
  percent?: number;
  error?: string;
  outcome?: {
    backup: string;
    oldVersion: string;
    newVersion: string;
    confirmed: boolean;
  };
}

export function fetchUpgradeProgress(name: string): Promise<UpgradeProgress> {
  return getJSON<UpgradeProgress>(
    `/api/devices/${encodeURIComponent(name)}/firmware/progress`,
  );
}

// Restore a stored backup onto the device (reboots it). 409s come back as a
// result rather than a thrown error so callers can branch on them; the
// important one is passwordReverts — the server refusing a snapshot that
// would roll the AP's login password back until the user explicitly agrees
// (resend with acceptPasswordRevert=true).
export interface RestoreResult {
  file?: string;
  rebooted?: boolean;
  // the restore rolled the AP's login password back to the snapshot's old one
  passwordReverted?: boolean;
  // 409-only: consent needed before a password rollback
  passwordReverts?: boolean;
  error?: string;
}

export async function restoreBackup(
  name: string,
  file: string,
  acceptPasswordRevert = false,
): Promise<RestoreResult> {
  const res = await apiFetch(`/api/devices/${encodeURIComponent(name)}/restore`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ file, acceptPasswordRevert }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok && res.status !== 409) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body;
}

// Network discovery: pre-auth TLS fingerprint sweep.
export interface DiscoverCandidate {
  ip: string;
  model: string;
  known: boolean;
}

export function discover(cidr: string): Promise<{ candidates: DiscoverCandidate[] }> {
  return getJSON<{ candidates: DiscoverCandidate[] }>(
    `/api/discover?cidr=${encodeURIComponent(cidr)}`,
  );
}

// Auth for the selfsight UI itself (server.auth in config.yaml).
export interface AuthStatus {
  required: boolean;
  authenticated: boolean;
}

export function fetchAuthStatus(): Promise<AuthStatus> {
  return getJSON<AuthStatus>("/api/auth/status");
}

export async function login(password: string): Promise<void> {
  const res = await apiFetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ password }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
}

export function logout(): Promise<{ ok: boolean }> {
  return postJSON<{ ok: boolean }>("/api/auth/logout");
}

// Inventory writes: selfsight edits config.yaml on the server (add/remove/edit
// a device) so the whole adopt-and-manage loop works from the dashboard. These
// return 501 if the server was started without a config path.
export interface DeviceInput {
  name: string;
  host: string;
  model?: string;
  // Pins the entry to a physical unit: recorded by the connection test, checked
  // by the server before apply/restore/upgrade. Blank on update means "keep".
  serial?: string;
  username: string;
  password?: string;
  desired?: {
    // hidden/enabled are tri-state: absent = not managed, true/false = enforce.
    ssids?: {
      name: string;
      vlan?: number;
      security?: string;
      // Sent only when setting a new one. The server never sends a stored
      // passphrase back — it reports hasPassphrase instead — and reads a
      // blank one on update as "keep the current".
      passphrase?: string;
      hasPassphrase?: boolean;
      hidden?: boolean;
      enabled?: boolean;
    }[];
    radios?: Record<string, { channel?: string; power?: string; enabled?: boolean }>;
  };
}

async function sendJSON<T>(method: string, path: string, body: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new StatusError(data.error ?? res.statusText, res.status);
  }
  return data as T;
}

// Full declared config for the edit form. It never carries a secret: the
// device password and every declared WiFi passphrase are reported only as
// hasPassword / hasPassphrase, so the form can offer "leave blank to keep"
// without the value ever reaching the browser.
export function fetchDeviceConfig(
  name: string,
): Promise<{ device: DeviceInput; hasPassword: boolean }> {
  return getJSON(`/api/devices/${encodeURIComponent(name)}/config`);
}

export function addDevice(dev: DeviceInput): Promise<{ device: string; devices: number }> {
  return sendJSON("POST", "/api/devices", dev);
}

export function updateDevice(name: string, dev: DeviceInput): Promise<{ device: string }> {
  return sendJSON("PUT", `/api/devices/${encodeURIComponent(name)}`, dev);
}

// Delete a wireless network from the device itself (guarded write: fresh
// backup first, read-back verified server-side). The server refuses the
// primary SSID and any SSID still declared in desired config.
export async function deleteDeviceSSID(
  device: string,
  ssid: string,
): Promise<{ applied?: boolean; observed?: string; error?: string }> {
  const res = await apiFetch(
    `/api/devices/${encodeURIComponent(device)}/ssids/${encodeURIComponent(ssid)}`,
    { method: "DELETE", headers: { Accept: "application/json" } },
  );
  const body = await res.json().catch(() => ({}));
  // A 409 is an answer, not a failure: the delete was written but the
  // read-back still sees the network, or the server refused it for a reason
  // worth showing. Same handling as applyDevice, so the UI renders both alike.
  if (!res.ok && res.status !== 409) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body;
}

export async function removeDevice(name: string): Promise<{ removed: string }> {
  const res = await apiFetch(`/api/devices/${encodeURIComponent(name)}`, {
    method: "DELETE",
    headers: { Accept: "application/json" },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body;
}

// Connection test: logs into an AP with typed credentials and reports what it
// found, without writing config. `ok:false` (with an error) for unreachable or
// Insight-managed devices.
export interface ConnectionTest {
  ok: boolean;
  host?: string;
  name?: string;
  serial?: string;
  firmware?: string;
  standalone?: boolean;
  model?: string;
  error?: string;
}

export async function testConnection(dev: DeviceInput): Promise<ConnectionTest> {
  const res = await apiFetch("/api/devices/test", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(dev),
  });
  const body = (await res.json().catch(() => ({}))) as ConnectionTest;
  // 409 (managed) / 502 (unreachable) still carry a useful body; surface it
  // as ok:false rather than throwing so the form can show the reason inline.
  if (!res.ok && res.status !== 409 && res.status !== 502) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body;
}

export async function fetchDeviceStatus(name: string): Promise<DeviceStatus> {
  const res = await apiFetch(`/api/devices/${encodeURIComponent(name)}/status`, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* keep statusText */
    }
    throw new StatusError(msg, res.status);
  }
  return (await res.json()) as DeviceStatus;
}

// The last reading the server saved for this device — served from disk, no AP
// contact. Lets the dashboard paint instantly while the live read runs.
export interface CachedStatus {
  fetchedAt: string;
  status: DeviceStatus;
}

export function fetchCachedStatus(name: string): Promise<CachedStatus> {
  return getJSON<CachedStatus>(
    `/api/devices/${encodeURIComponent(name)}/status/cached`,
  );
}

// Config change history: redacted snapshots of the device config over time,
// built by decrypting each backup. Secrets are fingerprinted, never stored.
export interface ConfigSnapshot {
  commit: string;
  when: string;
  message: string;
}

export function fetchConfigHistory(name: string): Promise<{ history: ConfigSnapshot[] }> {
  return getJSON<{ history: ConfigSnapshot[] }>(
    `/api/devices/${encodeURIComponent(name)}/history`,
  );
}

export function fetchConfigDiff(
  name: string,
  from: string,
  to: string,
): Promise<{ diff: string; summary?: string[] }> {
  const q = new URLSearchParams({ from, to }).toString();
  return getJSON<{ diff: string; summary?: string[] }>(
    `/api/devices/${encodeURIComponent(name)}/history/diff?${q}`,
  );
}

// One-off change straight to the AP — nothing is recorded in config.yaml.
// Same guarded pipeline as every write (backup first, read-back verified).
export interface DeviceChange {
  ssid?: {
    name: string;
    hidden?: boolean;
    enabled?: boolean;
    passphrase?: string;
    vlan?: number;
    security?: string;
  };
  radio?: { band: string; channel?: string; width?: string; enabled?: boolean };
}

export async function applyDeviceChange(
  name: string,
  change: DeviceChange,
): Promise<ApplyResponse> {
  const res = await apiFetch(`/api/devices/${encodeURIComponent(name)}/change`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(change),
  });
  const body = (await res.json().catch(() => ({}))) as ApplyResponse;
  if (!res.ok && res.status !== 409) {
    throw new StatusError(body.error ?? res.statusText, res.status);
  }
  return body;
}
