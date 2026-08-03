import {
  Anchor,
  AppShell,
  Badge,
  Button,
  Card,
  Checkbox,
  Container,
  Drawer,
  Group,
  Loader,
  Modal,
  NumberInput,
  PasswordInput,
  Progress,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { ChannelMap } from "./ChannelMap";
import { useSettleStatus } from "./useSettleStatus";
import {
  addDevice,
  applyDevice,
  applyDeviceChange,
  checkFirmware,
  deleteDeviceSSID,
  discover,
  fetchAuthStatus,
  fetchCachedStatus,
  fetchConfigDiff,
  fetchConfigHistory,
  fetchDeviceBackups,
  fetchDeviceConfig,
  fetchDeviceDrift,
  fetchDeviceStatus,
  fetchDevices,
  fetchUpgradeProgress,
  login,
  logout,
  reloadConfig,
  removeDevice,
  restoreBackup,
  setUnauthorizedHandler,
  startUpgrade,
  StatusError,
  takeDeviceBackup,
  testConnection,
  updateDevice,
  type ApplyResponse,
  type ConnectionTest,
  type Device,
  type DeviceChange,
  type DeviceInput,
  type DeviceStatus,
  type DriftReport,
  type Ssid,
} from "./api";

const SECURITY_OPTIONS = [
  { value: "open", label: "Open (no password)" },
  { value: "wpa2-psk", label: "WPA2-PSK" },
  { value: "wpa3-sae", label: "WPA3-SAE" },
  { value: "wpa2/wpa3", label: "WPA2/WPA3" },
];

export function App() {
  const qc = useQueryClient();
  const { data: auth, isLoading } = useQuery({
    queryKey: ["auth"],
    queryFn: fetchAuthStatus,
    retry: false,
  });
  // Any API 401 (a server restart wipes in-memory sessions) drops the UI back
  // to the login screen instead of leaving a cached, silently broken page.
  useEffect(() => {
    setUnauthorizedHandler(() => qc.invalidateQueries({ queryKey: ["auth"] }));
  }, [qc]);
  const reload = useMutation({
    mutationFn: reloadConfig,
    onSuccess: () => qc.invalidateQueries(),
  });
  const doLogout = useMutation({
    mutationFn: logout,
    onSuccess: () => qc.invalidateQueries(),
  });

  if (isLoading) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }
  if (auth?.required && !auth.authenticated) {
    return <LoginScreen />;
  }

  return (
    <AppShell header={{ height: 56 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Title order={3}>selfsight</Title>
          <Group gap="sm">
            {reload.isError && (
              <Text size="xs" c="red">
                {(reload.error as Error).message}
              </Text>
            )}
            <Button
              size="xs"
              variant="default"
              loading={reload.isPending}
              onClick={() => reload.mutate()}
            >
              Reload config
            </Button>
            {auth?.required && (
              <Button
                size="xs"
                variant="subtle"
                loading={doLogout.isPending}
                onClick={() => doLogout.mutate()}
              >
                Log out
              </Button>
            )}
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Main>
        <Container size="lg">
          <Fleet />
          <DiscoverPanel />
        </Container>
      </AppShell.Main>
    </AppShell>
  );
}

function LoginScreen() {
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const doLogin = useMutation({
    mutationFn: () => login(password),
    onSuccess: () => qc.invalidateQueries(),
  });
  return (
    <Container size="xs" mt={120}>
      <Card shadow="sm" padding="lg" radius="md" withBorder>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            doLogin.mutate();
          }}
        >
          <Stack gap="sm">
            <Title order={4}>selfsight</Title>
            <PasswordInput
              label="Password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              autoFocus
              data-testid="login-password"
            />
            {doLogin.isError && (
              <Text size="sm" c="red">
                {(doLogin.error as Error).message}
              </Text>
            )}
            <Button type="submit" loading={doLogin.isPending}>
              Log in
            </Button>
          </Stack>
        </form>
      </Card>
    </Container>
  );
}

function Fleet() {
  const [addOpen, setAddOpen] = useState(false);
  const { data, isLoading, error } = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
  });

  if (isLoading) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }
  if (error) {
    return (
      <Text c="red" mt="xl">
        Could not load devices: {(error as Error).message}
      </Text>
    );
  }
  const devices = data?.devices ?? [];

  return (
    <>
      <Group justify="space-between" mt="md">
        <Title order={4}>Access points</Title>
        <Button size="xs" onClick={() => setAddOpen(true)}>
          Add device
        </Button>
      </Group>
      {devices.length === 0 ? (
        <Text c="dimmed" mt="md">
          No devices yet. Click “Add device”, or discover them below.
        </Text>
      ) : (
        <>
          {devices.length > 1 && <ChannelMap devices={devices} />}
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} mt="md">
            {devices.map((d) => (
              <DeviceCard key={d.name} device={d} />
            ))}
          </SimpleGrid>
        </>
      )}
      <DeviceFormModal mode="add" opened={addOpen} onClose={() => setAddOpen(false)} />
    </>
  );
}

// ApLink opens the AP's own admin page. The AP refuses any address it has not
// been told to answer to, which is its IP plus — only if one is configured on
// the device — its FQDN. A DNS name the inventory happens to use is not enough
// and lands on a blank page. So prefer the AP's own FQDN when it has one, else
// the IP it reports, else the configured host as a last resort before the first
// reading. Either way the self-signed certificate raises the usual browser
// warning; that is expected and applies to the IP just the same.
function ApLink({
  host,
  reportedIP,
  fqdn,
}: {
  host: string;
  reportedIP?: string;
  fqdn?: string;
}) {
  const addr = fqdn || reportedIP || host;
  return (
    <Anchor
      href={`https://${addr}/`}
      target="_blank"
      rel="noreferrer"
      c="dimmed"
      underline="always"
      size="sm"
      title={
        addr === host
          ? "Open this AP's own web page"
          : `Open this AP's own web page — the inventory calls it ${host}, and it answers to ${addr}`
      }
    >
      {addr}
    </Anchor>
  );
}

function DeviceCard({ device }: { device: Device }) {
  const [detailOpen, setDetailOpen] = useState(false);
  // A radio re-tunes for tens of seconds after a change, so a single post-apply
  // refetch can still read the old channel; settle() polls the device's status
  // for a bounded window so the card and drawer converge without a reload.
  const settle = useSettleStatus();
  const live = useQuery({
    queryKey: ["status", device.name],
    queryFn: () => fetchDeviceStatus(device.name),
    retry: false,
  });
  // The server's saved last reading paints the card instantly (and keeps it
  // informative when the AP is unreachable) while the live read runs. It is a
  // display convenience only — the AP is the sole source of truth, and every
  // successful live read overwrites it.
  const cached = useQuery({
    queryKey: ["status-cached", device.name],
    queryFn: () => fetchCachedStatus(device.name),
    retry: false,
    staleTime: Infinity,
  });
  const { isLoading, error } = live;
  const data = live.data ?? cached.data?.status;
  const showingCached = !live.data && !!cached.data;

  // Drift only matters when the device declared a desired config; a device with
  // none simply reports in-sync with zero items. Skip fetching if unreachable.
  const { data: drift } = useQuery({
    queryKey: ["drift", device.name],
    queryFn: () => fetchDeviceDrift(device.name),
    retry: false,
    enabled: !!live.data, // needs the AP reachable; never fired by cached data
  });

  const managed = error instanceof StatusError && error.httpStatus === 409;
  const upgrading = error instanceof StatusError && error.httpStatus === 503;
  const badge = isLoading ? (
    <Badge color="gray" variant="light">
      checking…
    </Badge>
  ) : managed ? (
    <Badge color="yellow" variant="light">
      Insight-managed
    </Badge>
  ) : upgrading ? (
    <Badge color="orange" variant="light">
      upgrading…
    </Badge>
  ) : error ? (
    <Badge color="red" variant="light">
      unreachable
    </Badge>
  ) : (
    <Badge color="green" variant="light">
      online
    </Badge>
  );

  return (
    <Card shadow="sm" padding="lg" radius="md" withBorder>
      <Stack gap="xs">
        <Group justify="space-between">
          <Text fw={600}>{device.name}</Text>
          {badge}
        </Group>
        <Group justify="space-between">
          <Text size="sm" c="dimmed">
            <ApLink
              host={device.host}
              reportedIP={data?.system?.ip}
              fqdn={data?.system?.fqdn}
            />{" "}
            ·{" "}
            {device.model || "model unknown"}
          </Text>
          <DeviceActions device={device} />
        </Group>

        {error && !managed && !upgrading && (
          <Text size="xs" c="red">
            {(error as Error).message}
          </Text>
        )}
        {upgrading && <UpgradeProgressView device={device.name} />}
        {showingCached && (
          <Text size="xs" c="dimmed">
            showing last reading from{" "}
            {new Date(cached.data!.fetchedAt).toLocaleString()}
          </Text>
        )}

        {data && (
          <>
            <Group gap="lg" mt="xs">
              <Stat label="Firmware" value={data.system.firmware} />
              <Stat label="Clients" value={String(data.clients?.total ?? "—")} />
              <Stat label="Uptime" value={data.system.uptime} />
            </Group>
            {data.system.radios?.length > 0 && (
              <Table verticalSpacing={2} fz="xs" mt="xs">
                <Table.Tbody>
                  {data.system.radios.map((r) => (
                    <Table.Tr key={r.band}>
                      <Table.Td c="dimmed">{r.band}</Table.Td>
                      <Table.Td>{r.mode}</Table.Td>
                      <Table.Td>ch {r.channel}</Table.Td>
                      <Table.Td>{r.stations} clients</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
            {drift && <DriftBlock device={device.name} drift={drift} />}
            <FirmwareRow
              device={device.name}
              updateAvailable={!!data.firmware?.updateAvailable}
              availableImage={data.firmware?.availableImage ?? ""}
            />
            <BackupsRow device={device.name} />
            <Button
              size="compact-xs"
              variant="light"
              mt={2}
              onClick={() => setDetailOpen(true)}
            >
              All details →
            </Button>
            <DeviceDetailDrawer
              device={device}
              status={data}
              opened={detailOpen}
              onClose={() => setDetailOpen(false)}
              onApplied={() => settle(device.name)}
            />
          </>
        )}
      </Stack>
    </Card>
  );
}

// DeviceDetailDrawer is the full read-out for one AP — everything the driver
// reads, laid out the way Insight's device page does: identity/network, every
// radio's live state and settings, the SSID table, the client breakdown, and
// firmware. Management actions live on the card; this is the detail surface.
// QuickAction is one drawer-initiated change. Every write offers up to two
// exits, chosen in the confirmation dialog: "apply once" sends a one-off to
// the AP (nothing recorded — the AP stays the only record), while "save as
// managed" writes the declaration into config.yaml and then applies it.
// Actions that need a value (a channel, a passphrase) declare an input.
interface QuickAction {
  title: string;
  detail: string;
  input?: {
    label: string;
    placeholder?: string;
    initial?: string;
    secret?: boolean; // render as a password field
    minLength?: number; // confirm stays disabled below this
  };
  // The direct write for an unenforced field. Absent on actions that only
  // exist for enforced settings (e.g. applying a declared-but-missing network).
  makeChange?: (value: string) => DeviceChange;
  // When the field is enforced (declared in config.yaml), the change routes
  // here instead: the declaration is updated to the new value and applied, so
  // the change and the enforcement never fight. Invisible to the user — a
  // change is just a change.
  managedPatch?: (value: string) => Desired;
  enforced?: boolean;
}

// Local aliases into the DeviceInput shape: the declared config and one
// declared network's entry.
type Desired = DeviceInput["desired"];
type DeclaredSSID = NonNullable<NonNullable<Desired>["ssids"]>[number];

// SSIDEdit opens the network editor: adding a new network, or editing an
// observed one (carrying its current values for change detection).
interface SSIDEdit {
  mode: "add" | "edit";
  observed?: Ssid;
}

// The config's radio keys, from the driver's human band labels.
const BAND_KEY: Record<string, string> = { "2.4 GHz": "2g", "5 GHz": "5g", "6 GHz": "6g" };

function DeviceDetailDrawer({
  device,
  status,
  opened,
  onClose,
  onApplied,
}: {
  device: Device;
  status: DeviceStatus;
  opened: boolean;
  onClose: () => void;
  // Called after a change is written to the AP, so the parent can poll the
  // device's status until the radio settles on the new value.
  onApplied: () => void;
}) {
  const sys = status.system;
  // Merge live radio state (RadioStat) with per-band settings (RadioSetting).
  const settingByBand = new Map((status.radioSettings ?? []).map((r) => [r.band, r]));
  // Client counts keyed by SSID name (summed across bands).
  const clientsBySSID = new Map<string, number>();
  for (const c of status.clients?.perSSID ?? []) {
    clientsBySSID.set(c.ssid, (clientsBySSID.get(c.ssid) ?? 0) + c.count);
  }

  const qc = useQueryClient();

  // The drawer is the single per-device editing surface, so it needs the
  // declared config alongside the observed state: to badge managed fields,
  // to show declared-but-missing networks, and to build config updates for
  // the "save as managed" exit of every action.
  const config = useQuery({
    queryKey: ["device-config", device.name],
    queryFn: () => fetchDeviceConfig(device.name),
    enabled: opened,
    retry: false,
  });
  const desired = config.data?.device.desired;
  const declaredSSIDs = useMemo(() => desired?.ssids ?? [], [desired]);
  const declaredSSID = new Map(declaredSSIDs.map((s) => [s.name, s]));
  const declaredRadio = desired?.radios ?? {};

  const { data: drift } = useQuery({
    queryKey: ["drift", device.name],
    queryFn: () => fetchDeviceDrift(device.name),
    enabled: opened,
    retry: false,
  });
  const driftFor = (scope: string) =>
    (drift?.items ?? []).filter((i) => i.scope === scope && !i.inSync);

  // Deleting an SSID from the AP itself — guarded write (backup first,
  // read-back verified server-side; the primary SSID is refused there).
  const [ssidToDelete, setSsidToDelete] = useState<string | null>(null);
  const [delNote, setDelNote] = useState("");
  const delSsid = useMutation({
    mutationFn: (ssid: string) => deleteDeviceSSID(device.name, ssid),
    onSuccess: (res) => {
      // A refusal, or a delete the read-back could not confirm, comes back as
      // a body rather than a thrown error — show it instead of closing the
      // dialog as though the network were gone.
      if (res.error || res.applied === false) {
        setDelNote(
          res.error ??
            "the AP still reports this network — the delete was not confirmed",
        );
        return;
      }
      setDelNote("");
      setSsidToDelete(null);
      qc.invalidateQueries();
      onApplied();
    },
  });

  // Quick actions: change a setting straight from this drawer. The one-off
  // exit writes to the AP through the guarded pipeline (backup first,
  // read-back verified) with nothing recorded anywhere; the managed exit
  // stores the declaration in config.yaml first, then applies.
  const [pending, setPending] = useState<QuickAction | null>(null);
  const [inputVal, setInputVal] = useState("");
  const [quickResult, setQuickResult] = useState<ApplyResponse | null>(null);
  const [note, setNote] = useState("");
  const [editing, setEditing] = useState<SSIDEdit | null>(null);
  const [unmanage, setUnmanage] = useState<{ what: string; next: Desired } | null>(null);
  const quick = useMutation({
    mutationFn: (change: DeviceChange) => applyDeviceChange(device.name, change),
    onSuccess: (res) => {
      setQuickResult(res);
      setPending(null);
      setEditing(null);
      qc.invalidateQueries();
      onApplied();
    },
  });
  // The managed exit: store the new declaration, then (usually) apply it.
  // Applying runs the device's whole drift plan, so any other pending drift
  // is fixed in the same pass — the confirmation text says so.
  const managedSave = useMutation({
    mutationFn: async (args: { desired: Desired; apply: boolean }) => {
      const dev = config.data!.device;
      await updateDevice(device.name, { ...dev, password: "", desired: args.desired });
      return args.apply ? applyDevice(device.name) : null;
    },
    onSuccess: (res) => {
      setQuickResult(res);
      if (!res) setNote("saved to the config file — nothing was written to the AP");
      setPending(null);
      setEditing(null);
      setUnmanage(null);
      qc.invalidateQueries();
      if (res) onApplied(); // only when something was actually written to the AP
    },
  });
  const ask = (a: QuickAction) => {
    setQuickResult(null);
    setNote("");
    quick.reset(); // clear a previous attempt's error from the dialog
    managedSave.reset();
    setInputVal(a.input?.initial ?? "");
    setPending(a);
  };

  // Declaration surgery for the managed exits: replace/add one network's
  // declaration, drop one, and the same for a radio band.
  const patchSSID = (name: string, patch: Partial<DeclaredSSID>): Desired => {
    const idx = declaredSSIDs.findIndex((x) => x.name === name);
    const ssids =
      idx >= 0
        ? declaredSSIDs.map((x, i) => (i === idx ? { ...x, ...patch } : x))
        : [...declaredSSIDs, { name, ...patch }];
    return { ...desired, ssids };
  };
  const dropSSID = (name: string): Desired => ({
    ...desired,
    ssids: declaredSSIDs.filter((x) => x.name !== name),
  });
  const patchRadio = (key: string, patch: Record<string, unknown>): Desired => ({
    ...desired,
    radios: { ...declaredRadio, [key]: { ...declaredRadio[key], ...patch } },
  });
  const dropRadio = (key: string): Desired => {
    const radios = { ...declaredRadio };
    delete radios[key];
    return { ...desired, radios };
  };

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      // Wide enough that the radio/SSID tables (with their action buttons) fit
      // without horizontal scrolling; capped at the viewport on small screens.
      size="min(62rem, 100vw)"
      title={
        <Group gap="xs">
          <Text fw={700}>{device.name}</Text>
          <Text c="dimmed" size="sm">
            <ApLink host={device.host} reportedIP={sys?.ip} fqdn={sys?.fqdn} />
          </Text>
        </Group>
      }
    >
      <Stack gap="lg">
        {quickResult && (
          <Text size="xs" c={quickResult.results.every((r) => r.applied) ? "green" : "red"}>
            {quickResult.results.length === 0
              ? "Nothing to change — the device already matches."
              : quickResult.results
                  .map((r) => `${r.change}: ${r.applied ? "applied ✓" : `NOT confirmed (${r.observed})`}`)
                  .join("; ")}
            {quickResult.skipped?.length ? ` — skipped: ${quickResult.skipped.join(", ")}` : ""}
          </Text>
        )}
        {quick.isError && (
          <Text size="xs" c="red">
            {(quick.error as Error).message}
          </Text>
        )}
        {managedSave.isError && (
          <Text size="xs" c="red">
            {(managedSave.error as Error).message}
          </Text>
        )}
        {note && (
          <Text size="xs" c="green">
            {note}
          </Text>
        )}

        <Section title="Identity & network">
          <KV k="Model" v={device.model || sys.name} />
          <KV k="Serial" v={sys.serial} />
          <KV k="MAC" v={sys.mac} />
          <KV k="IP address" v={sys.ip} />
          <KV
            k="Gateway"
            v={sys.gateway ? `${sys.gateway} ${sys.gatewayUp ? "(up)" : "(down)"}` : "—"}
          />
          <KV k="Firmware" v={sys.firmware} />
          <KV k="Uptime" v={sys.uptime} />
          <KV k="Management" v={sys.standalone ? "Standalone (local)" : "Insight-managed"} />
          <KV k="Connected clients" v={String(sys.devices ?? status.clients?.total ?? "—")} />
        </Section>

        <Section title="Radios">
          <ScrollTable
            head={["Band", "Mode", "Channel", "Width", "Utilization", "Clients", "Radio", "Max", ""]}
            rows={(sys.radios ?? []).map((r) => {
              const s = settingByBand.get(r.band);
              const key = BAND_KEY[r.band] ?? r.band;
              const decl = declaredRadio[key];
              const isManaged = !!decl && (!!decl.channel || decl.enabled !== undefined);
              return [
                <Group key="b" gap={6} wrap="nowrap">
                  {r.band}
                  {isManaged && (
                    <Badge size="xs" variant="light">
                      enforced
                    </Badge>
                  )}
                  {driftFor("radio:" + key).length > 0 && (
                    <Badge size="xs" color="orange" variant="light">
                      out of sync
                    </Badge>
                  )}
                </Group>,
                r.mode || "—",
                r.channel || "—",
                r.channelWidth || "—",
                r.channelUtil || "—",
                String(r.stations ?? 0),
                s ? (s.on ? "on" : "off") : "—",
                s?.maxClients ? String(s.maxClients) : "—",
                <Group key="a" gap={4} wrap="nowrap">
                  <Button
                    size="compact-xs"
                    variant="subtle"
                    onClick={() =>
                      ask({
                        title: `Set ${r.band} channel on ${device.name}`,
                        detail: `Sets the channel on the AP.`,
                        input: {
                          label: "Channel",
                          placeholder: "e.g. 44, or auto",
                          initial: decl?.channel || r.channel || "",
                        },
                        makeChange: (ch) => ({
                          radio: { band: key, channel: ch },
                        }),
                        managedPatch: (ch) => patchRadio(key, { channel: ch }),
                        enforced: !!decl?.channel,
                      })
                    }
                  >
                    Channel
                  </Button>
                  {s && (
                    <Button
                      size="compact-xs"
                      variant="subtle"
                      color={s.on ? "red" : "green"}
                      onClick={() =>
                        ask({
                          title: `Turn ${r.band} radio ${s.on ? "OFF" : "on"} on ${device.name}`,
                          detail: s.on
                            ? `Turning the radio off disconnects every client on this band until it is turned back on.`
                            : `Turns the ${r.band} radio back on.`,
                          makeChange: () => ({
                            radio: { band: key, enabled: !s.on },
                          }),
                          managedPatch: () => patchRadio(key, { enabled: !s.on }),
                          enforced: decl?.enabled !== undefined,
                        })
                      }
                    >
                      {s.on ? "Turn off" : "Turn on"}
                    </Button>
                  )}
                  {isManaged && (
                    <Button
                      size="compact-xs"
                      variant="subtle"
                      color="gray"
                      onClick={() =>
                        setUnmanage({
                          what: `the ${r.band} radio settings`,
                          next: dropRadio(key),
                        })
                      }
                    >
                      Stop enforcing
                    </Button>
                  )}
                </Group>,
              ];
            })}
          />
        </Section>

        <Section title="Networks (SSIDs)">
          {(status.ssids && status.ssids.length > 0) || declaredSSIDs.length > 0 ? (
            <ScrollTable
              head={["Name", "Bands", "Security", "VLAN", "Hidden", "Enabled", "Clients", ""]}
              rows={[
                ...(status.ssids ?? []).map((s) => {
                  const decl = declaredSSID.get(s.name);
                  return [
                    <Group key="n" gap={6} wrap="nowrap">
                      {s.name}
                      {decl && (
                        <Badge size="xs" variant="light">
                          enforced
                        </Badge>
                      )}
                      {driftFor("ssid:" + s.name).length > 0 && (
                        <Badge size="xs" color="orange" variant="light">
                          out of sync
                        </Badge>
                      )}
                    </Group>,
                    (s.bands ?? []).join(", ") || "—",
                    s.security || "—",
                    s.vlan ? String(s.vlan) : "—",
                    s.hidden ? "yes" : "no",
                    s.enabled ? "yes" : "no",
                    String(clientsBySSID.get(s.name) ?? 0),
                    <Group key="a" gap={4} wrap="nowrap">
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        onClick={() => setEditing({ mode: "edit", observed: s })}
                      >
                        Edit
                      </Button>
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        onClick={() =>
                          ask({
                            title: `${s.hidden ? "Broadcast" : "Hide"} ${s.name} on ${device.name}`,
                            detail: s.hidden
                              ? `Makes ${s.name} visible in network scans again.`
                              : `Stops broadcasting ${s.name}; clients must type the name to join.`,
                            makeChange: () => ({
                              ssid: { name: s.name, hidden: !s.hidden },
                            }),
                            managedPatch: () => patchSSID(s.name, { hidden: !s.hidden }),
                            enforced: decl?.hidden !== undefined,
                          })
                        }
                      >
                        {s.hidden ? "Broadcast" : "Hide"}
                      </Button>
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        color={s.enabled ? "red" : "green"}
                        onClick={() =>
                          ask({
                            title: `${s.enabled ? "Disable" : "Enable"} ${s.name} on ${device.name}`,
                            detail: s.enabled
                              ? `Disabling ${s.name} disconnects every client on it (the network stays configured and can be re-enabled).`
                              : `Re-enables the ${s.name} network.`,
                            makeChange: () => ({
                              ssid: { name: s.name, enabled: !s.enabled },
                            }),
                            managedPatch: () => patchSSID(s.name, { enabled: !s.enabled }),
                            enforced: decl?.enabled !== undefined,
                          })
                        }
                      >
                        {s.enabled ? "Disable" : "Enable"}
                      </Button>
                      {decl ? (
                        <Button
                          size="compact-xs"
                          variant="subtle"
                          color="gray"
                          onClick={() =>
                            setUnmanage({
                              what: `the ${s.name} network settings`,
                              next: dropSSID(s.name),
                            })
                          }
                        >
                          Stop enforcing
                        </Button>
                      ) : (
                        <Button
                          key="del"
                          size="compact-xs"
                          variant="subtle"
                          color="red"
                          onClick={() => setSsidToDelete(s.name)}
                        >
                          Delete
                        </Button>
                      )}
                    </Group>,
                  ];
                }),
                // Declared networks the AP doesn't have (yet): shown from the
                // declaration, with Apply to create them on the device.
                ...declaredSSIDs
                  .filter((d) => !(status.ssids ?? []).some((s) => s.name === d.name))
                  .map((d) => [
                    <Group key="n" gap={6} wrap="nowrap">
                      {d.name}
                      <Badge size="xs" variant="light">
                        enforced
                      </Badge>
                      <Badge size="xs" color="orange" variant="light">
                        not on AP
                      </Badge>
                    </Group>,
                    "—",
                    d.security || "—",
                    d.vlan ? String(d.vlan) : "—",
                    d.hidden === undefined ? "—" : d.hidden ? "yes" : "no",
                    d.enabled === undefined ? "—" : d.enabled ? "yes" : "no",
                    "—",
                    <Group key="a" gap={4} wrap="nowrap">
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        color="orange"
                        onClick={() =>
                          ask({
                            title: `Create ${d.name} on ${device.name}`,
                            detail: `This network is enforced by selfsight but missing from the AP. Applying creates it (and fixes anything else out of sync on this device).`,
                            managedPatch: () => desired,
                            enforced: true,
                          })
                        }
                      >
                        Apply
                      </Button>
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        color="gray"
                        onClick={() =>
                          setUnmanage({
                            what: `the ${d.name} network settings`,
                            next: dropSSID(d.name),
                          })
                        }
                      >
                        Stop enforcing
                      </Button>
                    </Group>,
                  ]),
              ]}
            />
          ) : (
            <Text size="sm" c="dimmed">
              No SSIDs reported.
            </Text>
          )}
          <Button
            size="compact-xs"
            variant="light"
            style={{ alignSelf: "flex-start" }}
            onClick={() => setEditing({ mode: "add" })}
          >
            + Add network
          </Button>
          {(delSsid.isError || delNote) && (
            <Text size="sm" c="red">
              {delNote || (delSsid.error as Error).message}
            </Text>
          )}
          <ConfirmModal
            opened={ssidToDelete !== null}
            onClose={() => {
              setSsidToDelete(null);
              setDelNote("");
            }}
            device={ssidToDelete ?? ""}
            title={`Delete SSID ${ssidToDelete} from ${device.name}`}
            confirmLabel="Delete from AP"
            color="red"
            busy={delSsid.isPending}
            onConfirm={() => ssidToDelete && delSsid.mutate(ssidToDelete)}
          >
            <Text size="sm">
              This removes the wireless network <b>{ssidToDelete}</b> from the
              access point itself — every client on it disconnects, and the
              write briefly bounces the radio. A fresh config backup is taken
              first, and the result is verified by read-back. The AP's primary
              network cannot be deleted.
            </Text>
            {(delSsid.isError || delNote) && (
              <Text size="sm" c="red" mt="xs">
                {delNote || (delSsid.error as Error).message}
              </Text>
            )}
          </ConfirmModal>
        </Section>

        <ConfirmModal
          opened={pending !== null}
          onClose={() => setPending(null)}
          device={device.name}
          title={pending?.title ?? ""}
          confirmLabel="Apply"
          color="orange"
          busy={quick.isPending || managedSave.isPending}
          disabled={
            !!pending?.input &&
            inputVal.trim().length < (pending.input.minLength ?? 1)
          }
          onConfirm={() => {
            if (!pending) return;
            if (pending.enforced && pending.managedPatch) {
              managedSave.mutate({
                desired: pending.managedPatch(inputVal.trim()),
                apply: true,
              });
            } else if (pending.makeChange) {
              quick.mutate(pending.makeChange(inputVal.trim()));
            }
          }}
        >
          <Text size="sm">{pending?.detail}</Text>
          {pending?.input &&
            (pending.input.secret ? (
              <PasswordInput
                label={pending.input.label}
                placeholder={pending.input.placeholder}
                value={inputVal}
                onChange={(e) => setInputVal(e.currentTarget.value)}
                mt="xs"
              />
            ) : (
              <TextInput
                label={pending.input.label}
                placeholder={pending.input.placeholder}
                value={inputVal}
                onChange={(e) => setInputVal(e.currentTarget.value)}
                mt="xs"
              />
            ))}
          <Text size="sm" mt="xs">
            {pending?.enforced
              ? "This setting is enforced by selfsight, so the new value is also saved in its config file — selfsight keeps it this way from now on (and fixes anything else out of sync on this device in the same pass). A fresh backup is taken first and every write is checked by reading it back. Wireless changes briefly interrupt Wi-Fi on this AP, and confirming can take a minute while it restarts."
              : "This changes the access point directly. A fresh backup is taken first and the write is checked by reading it back. Wireless changes briefly interrupt Wi-Fi on this AP, and confirming can take a minute while it restarts."}
          </Text>
          {quick.isError && (
            <Text size="sm" c="red" mt="xs">
              {(quick.error as Error).message}
            </Text>
          )}
          {managedSave.isError && (
            <Text size="sm" c="red" mt="xs">
              {(managedSave.error as Error).message}
            </Text>
          )}
        </ConfirmModal>

        <ConfirmModal
          opened={unmanage !== null}
          onClose={() => setUnmanage(null)}
          device={device.name}
          title={`Stop enforcing ${unmanage?.what ?? ""}`}
          confirmLabel="Stop enforcing"
          color="orange"
          busy={managedSave.isPending}
          onConfirm={() =>
            unmanage && managedSave.mutate({ desired: unmanage.next, apply: false })
          }
        >
          <Text size="sm">
            This removes the setting from selfsight's config file. Nothing is
            written to the access point — everything stays as it is right now,
            but selfsight stops checking it and putting it back.
          </Text>
          {managedSave.isError && (
            <Text size="sm" c="red" mt="xs">
              {(managedSave.error as Error).message}
            </Text>
          )}
        </ConfirmModal>

        <SSIDEditorModal
          device={device.name}
          edit={editing}
          declared={editing?.observed ? declaredSSID.get(editing.observed.name) : undefined}
          busy={quick.isPending || managedSave.isPending}
          errorText={
            quick.isError
              ? (quick.error as Error).message
              : managedSave.isError
                ? (managedSave.error as Error).message
                : ""
          }
          onClose={() => setEditing(null)}
          onOnce={(change) => quick.mutate(change)}
          onManaged={(name, decl) =>
            managedSave.mutate({ desired: patchSSID(name, decl), apply: true })
          }
        />

        <Section title={`Connected clients (${status.clientList?.length ?? status.clients?.total ?? 0})`}>
          {status.clientList && status.clientList.length > 0 ? (
            <ScrollTable
              head={["Host", "IP", "MAC", "SSID", "Band", "OS", "VLAN"]}
              rows={status.clientList.map((c) => [
                c.hostname || "—",
                c.ip || "—",
                c.mac,
                c.ssid || "—",
                c.band || "—",
                c.os || "—",
                c.vlan ? String(c.vlan) : "—",
              ])}
            />
          ) : (
            <Text size="sm" c="dimmed">
              {status.clients?.total
                ? `${status.clients.total} connected (per-client detail unavailable)`
                : "No clients connected."}
            </Text>
          )}
        </Section>

        <Section title="Firmware">
          <KV k="Current" v={sys.firmware} />
          <KV
            k="Update"
            v={
              status.firmware?.updateAvailable
                ? `available: ${status.firmware.availableImage}`
                : "up to date"
            }
          />
          {status.firmware?.lastChecked && (
            <KV k="Last checked" v={status.firmware.lastChecked} />
          )}
          {status.firmware?.releaseNotesURL && (
            <Group justify="space-between">
              <Text size="sm" c="dimmed">
                Release notes
              </Text>
              <Anchor size="sm" href={status.firmware.releaseNotesURL} target="_blank">
                link
              </Anchor>
            </Group>
          )}
        </Section>

        <Section title="Config history">
          <ConfigHistoryPanel device={device.name} />
        </Section>
      </Stack>
    </Drawer>
  );
}

// toSecurityValue maps the driver's observed security label (e.g.
// "WPA2-PSK/AES") onto the config vocabulary the Select uses.
const toSecurityValue = (label: string): string | null => {
  const l = label.toLowerCase();
  if (l.startsWith("open")) return "open";
  if (l.startsWith("wpa2/wpa3")) return "wpa2/wpa3";
  if (l.startsWith("wpa3")) return "wpa3-sae";
  if (l.startsWith("wpa2")) return "wpa2-psk";
  return null;
};

// SSIDEditorModal adds a network or edits an observed one, with the same two
// exits as every drawer write: apply once to the AP (only what changed is
// sent, nothing recorded), or save as managed (the form's fields become the
// network's declaration in config.yaml, then get applied).
function SSIDEditorModal({
  device,
  edit,
  declared,
  busy,
  errorText,
  onClose,
  onOnce,
  onManaged,
}: {
  device: string;
  edit: SSIDEdit | null;
  declared?: DeclaredSSID;
  busy: boolean;
  errorText: string;
  onClose: () => void;
  onOnce: (change: DeviceChange) => void;
  onManaged: (name: string, decl: Partial<DeclaredSSID>) => void;
}) {
  const [name, setName] = useState("");
  const [security, setSecurity] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [vlan, setVlan] = useState<number | "">("");
  const [hidden, setHidden] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [typed, setTyped] = useState("");

  const obs = edit?.observed;
  useEffect(() => {
    if (!edit) return;
    setTyped("");
    setPassphrase("");
    if (edit.mode === "add") {
      setName("");
      setSecurity("wpa2-psk");
      setVlan("");
      setHidden(false);
      setEnabled(true);
    } else if (obs) {
      setName(obs.name);
      setSecurity(toSecurityValue(obs.security));
      setVlan(obs.vlan || "");
      setHidden(obs.hidden);
      setEnabled(obs.enabled);
    }
    // `edit` is a fresh object per open, so every open reinitializes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edit]);

  if (!edit) return null;

  // An enforced network's edits route through the config file (declaration
  // updated to the new values, then applied) so the change and the
  // enforcement never fight; anything else is written straight to the AP.
  const enforced = edit.mode === "edit" && !!declared;

  // The one-time exit sends only what changed against the observed state (a
  // field the user didn't touch is not written); adding sends every field.
  const onceChange = (): NonNullable<DeviceChange["ssid"]> => {
    const ch: NonNullable<DeviceChange["ssid"]> = { name };
    if (passphrase) ch.passphrase = passphrase;
    if (edit.mode === "add") {
      if (security) ch.security = security;
      if (vlan) ch.vlan = vlan;
      ch.hidden = hidden;
      ch.enabled = enabled;
    } else if (obs) {
      if (security && security !== toSecurityValue(obs.security)) ch.security = security;
      if (vlan && vlan !== obs.vlan) ch.vlan = vlan;
      if (hidden !== obs.hidden) ch.hidden = hidden;
      if (enabled !== obs.enabled) ch.enabled = enabled;
    }
    return ch;
  };
  const dirty = Object.keys(onceChange()).length > 1;

  // The enforce exit declares exactly what the form shows. A blank passphrase
  // is left out entirely, which the server reads as "keep the declared one" —
  // the browser is never sent the stored value to echo back.
  const managedDecl = (): Partial<DeclaredSSID> => ({
    security: security ?? undefined,
    passphrase: passphrase || undefined,
    vlan: vlan || undefined,
    hidden,
    enabled,
  });

  const needsKey =
    security !== null && security !== "open" && !passphrase && !declared?.hasPassphrase;
  const invalid =
    !name.trim() ||
    (passphrase !== "" && (passphrase.length < 8 || passphrase.length > 63)) ||
    (edit.mode === "add" && (!security || (security !== "open" && passphrase.length < 8))) ||
    (edit.mode === "edit" && !enforced && !dirty) ||
    (enforced && needsKey);

  return (
    <Modal
      opened
      onClose={onClose}
      title={edit.mode === "add" ? `Add a network on ${device}` : `Edit ${obs?.name} on ${device}`}
      centered
    >
      <Stack gap="sm">
        <Group grow>
          <TextInput
            label="Name (SSID)"
            value={name}
            disabled={edit.mode === "edit"}
            onChange={(e) => setName(e.currentTarget.value)}
          />
          <NumberInput
            label="VLAN"
            placeholder="1"
            min={1}
            max={4094}
            value={vlan}
            onChange={(v) => setVlan(typeof v === "number" ? v : "")}
          />
        </Group>
        <Group grow>
          <Select
            label="Security"
            data={SECURITY_OPTIONS}
            value={security}
            onChange={setSecurity}
          />
          <PasswordInput
            label="Passphrase"
            placeholder={
              edit.mode === "edit"
                ? declared?.hasPassphrase
                  ? "leave blank to keep declared"
                  : "leave blank to keep current"
                : "8–63 characters"
            }
            value={passphrase}
            onChange={(e) => setPassphrase(e.currentTarget.value)}
          />
        </Group>
        <Group gap="xl">
          <Checkbox
            label="Enabled"
            checked={enabled}
            onChange={(e) => setEnabled(e.currentTarget.checked)}
          />
          <Checkbox
            label="Hidden (not shown in network scans)"
            checked={hidden}
            onChange={(e) => setHidden(e.currentTarget.checked)}
          />
        </Group>
        <Text size="xs" c="dimmed">
          {enforced
            ? "This network is enforced by selfsight, so these values are also saved in its config file and kept this way from now on. A fresh backup is taken first and every write is checked by reading it back. Wireless changes briefly interrupt Wi-Fi on this AP, and confirming can take a minute while it restarts."
            : "This changes the access point directly. A fresh backup is taken first and the write is checked by reading it back. Wireless changes briefly interrupt Wi-Fi on this AP, and confirming can take a minute while it restarts."}
        </Text>
        <TextInput
          label={`Type "${device}" to confirm`}
          value={typed}
          onChange={(e) => setTyped(e.currentTarget.value)}
        />
        {errorText && (
          <Text size="sm" c="red">
            {errorText}
          </Text>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            color="orange"
            loading={busy}
            disabled={typed !== device || invalid}
            onClick={() =>
              enforced
                ? onManaged(name.trim(), managedDecl())
                : onOnce({ ssid: onceChange() })
            }
          >
            Apply
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// ConfigHistoryPanel shows the device's config snapshots (decrypted from each
// backup, secrets redacted) and the change between the two most recent, with a
// picker to compare any two. Empty until at least one backup has been recorded.
function ConfigHistoryPanel({ device }: { device: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["history", device],
    queryFn: () => fetchConfigHistory(device),
    retry: false,
  });
  const snaps = data?.history ?? [];
  // Default comparison: newest vs the most recent snapshot that actually
  // differs from it — "the latest change". Adjacent snapshots can compare
  // equal (their only differences are volatile bookkeeping the diff hides),
  // so From auto-walks back until the diff is non-empty; a manual pick stops
  // the walking.
  const [from, setFrom] = useState<string>("");
  const [to, setTo] = useState<string>("");
  const [autoFrom, setAutoFrom] = useState(true);
  useEffect(() => {
    setAutoFrom(true);
    if (snaps.length >= 2) {
      setTo(snaps[0].commit);
      setFrom(snaps[1].commit);
    } else if (snaps.length === 1) {
      setTo(snaps[0].commit);
      setFrom("");
    }
  }, [data]); // eslint-disable-line react-hooks/exhaustive-deps
  const diff = useQuery({
    queryKey: ["history-diff", device, from, to],
    queryFn: () => fetchConfigDiff(device, from, to),
    enabled: !!to,
    retry: false,
  });
  useEffect(() => {
    if (!autoFrom || !diff.data || !from) return;
    if (diff.data.diff.trim() !== "") {
      setAutoFrom(false); // found the latest change
      return;
    }
    const idx = snaps.findIndex((s) => s.commit === from);
    if (idx >= 0 && idx + 1 < snaps.length) {
      setFrom(snaps[idx + 1].commit);
    } else {
      setAutoFrom(false); // walked to the oldest — truly no changes
    }
  }, [diff.data]); // eslint-disable-line react-hooks/exhaustive-deps

  if (isLoading) return <Loader size="xs" />;
  if (snaps.length === 0)
    return (
      <Text size="sm" c="dimmed">
        No snapshots yet — the history is built from config backups.
      </Text>
    );

  const opts = snaps.map((s) => ({
    value: s.commit,
    label: new Date(s.when).toLocaleString(),
  }));
  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed">
        {snaps.length} snapshot{snaps.length === 1 ? "" : "s"} (one per config
        backup) · each line is one AP setting: ~ changed (old → new), + added,
        − removed · passphrases show as fingerprints, never values
      </Text>
      <Group gap="xs" wrap="nowrap" align="end">
        <Select
          size="xs"
          label="From"
          data={[{ value: "", label: "(nothing)" }, ...opts]}
          value={from}
          onChange={(v) => {
            setAutoFrom(false);
            setFrom(v ?? "");
          }}
          allowDeselect={false}
          w={200}
        />
        <Select
          size="xs"
          label="To"
          data={opts}
          value={to}
          onChange={(v) => {
            setAutoFrom(false);
            setTo(v ?? "");
          }}
          allowDeselect={false}
          w={200}
        />
      </Group>
      {diff.isLoading ? (
        <Loader size="xs" />
      ) : diff.data ? (
        diff.data.diff.trim() === "" ? (
          <Text size="sm" c="dimmed">
            No configuration changes between these snapshots.
          </Text>
        ) : (
          <>
            {(diff.data.summary?.length ?? 0) > 0 && (
              <Stack gap={2}>
                {diff.data.summary!.map((s) => (
                  <Text key={s} size="sm">
                    • {s}
                  </Text>
                ))}
              </Stack>
            )}
            {(diff.data.summary?.length ?? 0) > 0 && (
              <Text size="xs" c="dimmed" mt={4}>
                Raw settings behind this:
              </Text>
            )}
            <Table.ScrollContainer minWidth={0} type="native">
              <Text
                component="pre"
                size="xs"
                ff="monospace"
                style={{ whiteSpace: "pre", margin: 0 }}
              >
                {diff.data.diff
                  .split("\n")
                  .map((line, i) => (
                    <Text
                      key={i}
                      component="span"
                      size="xs"
                      ff="monospace"
                      c={line.startsWith("+") ? "green" : line.startsWith("-") ? "red" : "dimmed"}
                      style={{ display: "block" }}
                    >
                      {line}
                    </Text>
                  ))}
              </Text>
            </Table.ScrollContainer>
          </>
        )
      ) : null}
    </Stack>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Stack gap={6}>
      <Text fw={600} size="sm" tt="uppercase" c="dimmed">
        {title}
      </Text>
      {children}
    </Stack>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <Group justify="space-between" gap="xs" wrap="nowrap">
      <Text size="sm" c="dimmed">
        {k}
      </Text>
      <Text size="sm" style={{ textAlign: "right" }}>
        {v || "—"}
      </Text>
    </Group>
  );
}

function ScrollTable({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    // type="native" shows a real scrollbar when a table overflows — the default
    // overlay scrollbar is invisible until hover, so wide tables looked chopped.
    <Table.ScrollContainer minWidth={0} type="native">
      <Table fz="xs" verticalSpacing={4} striped>
        <Table.Thead>
          <Table.Tr>
            {head.map((h) => (
              <Table.Th key={h}>{h}</Table.Th>
            ))}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((row, i) => (
            <Table.Tr key={i}>
              {row.map((cell, j) => (
                <Table.Td key={j}>{cell}</Table.Td>
              ))}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

// DriftBlock shows the drift verdict and, when out of sync, the guarded Apply
// action: every write is preceded by a fresh device backup and verified by
// read-back, and wireless writes briefly bounce the radio.
function DriftBlock({ device, drift }: { device: string; drift: DriftReport }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<ApplyResponse | null>(null);
  const apply = useMutation({
    mutationFn: () => applyDevice(device),
    onSuccess: (res) => {
      setResult(res);
      qc.invalidateQueries({ queryKey: ["status", device] });
      qc.invalidateQueries({ queryKey: ["drift", device] });
      qc.invalidateQueries({ queryKey: ["backups", device] });
    },
  });

  const items = (drift.items ?? []).filter((i) => !i.inSync);
  if (items.length === 0 && !result) {
    return (drift.items?.length ?? 0) > 0 ? (
      <Badge color="green" variant="dot" mt="xs">
        config in sync
      </Badge>
    ) : null;
  }

  return (
    <Stack gap={4} mt="xs">
      <Group gap="xs" justify="space-between">
        {items.length > 0 ? (
          <Badge color="orange" variant="light">
            {items.length} config drift
          </Badge>
        ) : (
          <Badge color="green" variant="dot">
            config in sync
          </Badge>
        )}
        {items.length > 0 && (
          <Button size="compact-xs" color="orange" onClick={() => setOpen(true)}>
            Apply…
          </Button>
        )}
      </Group>
      {items.map((i) => (
        <Text key={`${i.scope}.${i.field}`} size="xs" c="orange">
          {i.scope} {i.field}: want {i.desired}, got {i.observed}
        </Text>
      ))}
      {result && (
        <Text size="xs" c={result.results.every((r) => r.applied) ? "green" : "red"}>
          {result.results.map((r) => `${r.change}: ${r.applied ? "applied" : `NOT confirmed (${r.observed})`}`).join("; ")}
          {result.skipped?.length ? ` — skipped: ${result.skipped.join(", ")}` : ""}
        </Text>
      )}
      {apply.isError && (
        <Text size="xs" c="red">
          {(apply.error as Error).message}
        </Text>
      )}

      <ConfirmModal
        opened={open}
        onClose={() => setOpen(false)}
        device={device}
        title={`Apply declared config to ${device}`}
        confirmLabel="Apply"
        color="orange"
        busy={apply.isPending}
        onConfirm={() => {
          setOpen(false);
          apply.mutate();
        }}
      >
        <Text size="sm">
          This writes to the access point. Each change takes a fresh device
          backup first and is verified by read-back. Wireless changes briefly
          bounce the radio — clients on this AP will drop and rejoin.
        </Text>
        <Stack gap={2} mt="xs">
          {items.map((i) => (
            <Text key={`${i.scope}.${i.field}`} size="xs">
              • {i.scope} {i.field}: {i.observed} → {i.desired}
            </Text>
          ))}
        </Stack>
      </ConfirmModal>
    </Stack>
  );
}

// FirmwareRow: deliberate cloud check plus the upgrade flow with progress.
function FirmwareRow({
  device,
  updateAvailable,
  availableImage,
}: {
  device: string;
  updateAvailable: boolean;
  availableImage: string;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [watching, setWatching] = useState(false);
  const check = useMutation({
    mutationFn: () => checkFirmware(device),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["status", device] }),
  });
  const upgrade = useMutation({
    mutationFn: () => startUpgrade(device),
    onSuccess: () => setWatching(true),
  });

  return (
    <Stack gap={4}>
      <Group gap="xs" justify="space-between">
        {updateAvailable ? (
          <Badge color="orange" variant="light">
            update available: {availableImage}
          </Badge>
        ) : (
          <Text size="xs" c="dimmed">
            firmware up to date{check.isError ? ` — ${(check.error as Error).message}` : ""}
          </Text>
        )}
        <Group gap="xs">
          <Button
            size="compact-xs"
            variant="light"
            loading={check.isPending}
            onClick={() => check.mutate()}
          >
            Check firmware
          </Button>
          {updateAvailable && (
            <Button size="compact-xs" color="red" onClick={() => setOpen(true)}>
              Upgrade…
            </Button>
          )}
        </Group>
      </Group>
      {upgrade.isError && (
        <Text size="xs" c="red">
          {(upgrade.error as Error).message}
        </Text>
      )}
      {watching && <UpgradeProgressView device={device} onDone={() => setWatching(false)} />}

      <ConfirmModal
        opened={open}
        onClose={() => setOpen(false)}
        device={device}
        title={`Upgrade firmware on ${device}`}
        confirmLabel="Flash it"
        color="red"
        busy={upgrade.isPending}
        onConfirm={() => {
          setOpen(false);
          upgrade.mutate();
        }}
      >
        <Text size="sm">
          This flashes <b>{availableImage}</b> and <b>reboots the AP</b>: every
          client on it drops, and an interrupted flash can require physical
          recovery. A fresh config backup is taken first. Upgrades run one AP
          at a time — the whole fleet shares one slot.
        </Text>
      </ConfirmModal>
    </Stack>
  );
}

function UpgradeProgressView({ device, onDone }: { device: string; onDone?: () => void }) {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["upgrade", device],
    queryFn: () => fetchUpgradeProgress(device),
    refetchInterval: (q) => (q.state.data?.running === false ? false : 2000),
  });
  if (!data) return null;
  if (data.running) {
    return (
      <Stack gap={2}>
        <Text size="xs" c="dimmed">
          {data.phase ?? "starting"} {data.percent != null ? `${data.percent}%` : ""}
        </Text>
        <Progress value={data.percent ?? 0} animated />
      </Stack>
    );
  }
  const oc = data.outcome;
  return (
    <Text
      size="xs"
      c={data.error ? "red" : oc?.confirmed ? "green" : "orange"}
      onClick={() => {
        qc.invalidateQueries({ queryKey: ["status", device] });
        onDone?.();
      }}
    >
      {data.error
        ? `upgrade failed: ${data.error}`
        : oc
          ? `upgrade ${oc.confirmed ? "confirmed" : "NOT confirmed"}: ${oc.oldVersion} → ${oc.newVersion || "?"}`
          : ""}
    </Text>
  );
}

// BackupsRow shows how many config archives the server holds for this device,
// lets the user pull a fresh one (read-only on the AP), and offers the restore
// flow (which reboots the AP).
function BackupsRow({ device }: { device: string }) {
  const qc = useQueryClient();
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [revertOpen, setRevertOpen] = useState(false);
  const [file, setFile] = useState<string | null>(null);
  const [restoreResult, setRestoreResult] = useState("");
  const [restoreProblem, setRestoreProblem] = useState("");
  const { data } = useQuery({
    queryKey: ["backups", device],
    queryFn: () => fetchDeviceBackups(device),
    retry: false,
  });
  const backup = useMutation({
    mutationFn: () => takeDeviceBackup(device),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["backups", device] }),
  });
  const restore = useMutation({
    mutationFn: (acceptPasswordRevert: boolean) =>
      restoreBackup(device, file!, acceptPasswordRevert),
    onSuccess: (res) => {
      // The server refuses a snapshot that would roll the AP's login password
      // back until the user explicitly agrees — ask, then resend.
      if (res.passwordReverts) {
        setRevertOpen(true);
        return;
      }
      if (res.error && !res.rebooted) {
        setRestoreProblem(res.error);
        return;
      }
      let msg = res.rebooted
        ? "restore confirmed: the device rebooted onto the archive"
        : "restore did NOT take: the device never rebooted (old session still valid)";
      if (res.passwordReverted) {
        msg +=
          " — the AP's login password has rolled back to the snapshot's old one; update the password selfsight uses for this device";
      }
      setRestoreResult(msg);
      qc.invalidateQueries({ queryKey: ["status", device] });
      qc.invalidateQueries({ queryKey: ["backups", device] });
    },
  });

  const entries = data?.backups ?? [];
  const last = entries[0];
  return (
    <Stack gap={4}>
      <Group gap="xs" justify="space-between">
        <Text size="xs" c="dimmed">
          {entries.length === 0
            ? "no backups stored"
            : `${entries.length} backup${entries.length > 1 ? "s" : ""} · last ${new Date(last.modified).toLocaleString()}`}
        </Text>
        <Group gap="xs">
          <Button
            size="compact-xs"
            variant="light"
            loading={backup.isPending}
            onClick={() => backup.mutate()}
          >
            Backup now
          </Button>
          {entries.length > 0 && (
            <Button
              size="compact-xs"
              variant="light"
              color="red"
              onClick={() => setRestoreOpen(true)}
            >
              Restore…
            </Button>
          )}
        </Group>
      </Group>
      {backup.isError && (
        <Text size="xs" c="red">
          {(backup.error as Error).message}
        </Text>
      )}
      {restore.isError && (
        <Text size="xs" c="red">
          {(restore.error as Error).message}
        </Text>
      )}
      {restoreProblem && (
        <Text size="xs" c="red">
          {restoreProblem}
        </Text>
      )}
      {restoreResult && (
        <Text size="xs" c={restoreResult.includes("NOT") ? "red" : "green"}>
          {restoreResult}
        </Text>
      )}

      <ConfirmModal
        opened={restoreOpen}
        onClose={() => setRestoreOpen(false)}
        device={device}
        title={`Restore a backup onto ${device}`}
        confirmLabel="Restore"
        color="red"
        busy={restore.isPending}
        disabled={!file}
        onConfirm={() => {
          setRestoreOpen(false);
          setRestoreResult("");
          setRestoreProblem("");
          restore.mutate(false);
        }}
      >
        <Text size="sm">
          Restoring <b>reboots the AP</b> and drops every wireless client on
          it. The snapshot is re-encrypted with the device's current admin
          password on the way out. Success is confirmed only by the reboot
          itself (the AP's own answer is not trusted).
        </Text>
        <Select
          mt="xs"
          label="Archive"
          placeholder="pick a stored backup"
          data={entries.map((e) => ({
            value: e.file,
            label: `${e.file} (${new Date(e.modified).toLocaleString()})`,
          }))}
          value={file}
          onChange={setFile}
        />
      </ConfirmModal>

      <ConfirmModal
        opened={revertOpen}
        onClose={() => setRevertOpen(false)}
        device={device}
        title={`This restore rolls back the login password on ${device}`}
        confirmLabel="Restore anyway"
        color="red"
        busy={restore.isPending}
        onConfirm={() => {
          setRevertOpen(false);
          restore.mutate(true);
        }}
      >
        <Text size="sm">
          This snapshot was taken when <b>{device}</b> had a <b>different admin
          password</b>. Restoring it puts that old password back on the device
          — the current one will stop working, and you must update the
          password selfsight is configured with (or the device becomes
          unreachable from here). Only continue if you know the old password.
        </Text>
      </ConfirmModal>
    </Stack>
  );
}

// ConfirmModal is the shared scary-action gate: the user must type the device
// name before the destructive button arms.
function ConfirmModal({
  opened,
  onClose,
  device,
  title,
  confirmLabel,
  color,
  busy,
  disabled,
  onConfirm,
  children,
}: {
  opened: boolean;
  onClose: () => void;
  device: string;
  title: string;
  confirmLabel: string;
  color: string;
  busy?: boolean;
  disabled?: boolean;
  onConfirm: () => void;
  children: React.ReactNode;
}) {
  const [typed, setTyped] = useState("");
  return (
    <Modal opened={opened} onClose={onClose} title={title} centered>
      <Stack gap="sm">
        {children}
        <TextInput
          label={`Type "${device}" to confirm`}
          value={typed}
          onChange={(e) => setTyped(e.currentTarget.value)}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            color={color}
            disabled={typed !== device || disabled}
            loading={busy}
            onClick={() => {
              setTyped("");
              onConfirm();
            }}
          >
            {confirmLabel}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// DiscoverPanel sweeps a subnet for WAX APs (pre-auth TLS fingerprint). Each
// AP not already in the inventory gets an "Add" button that opens the
// add-device form prefilled with its address — selfsight then writes it into
// config.yaml for you.
function DiscoverPanel() {
  const [cidr, setCidr] = useState("");
  const [addFor, setAddFor] = useState<{ host: string; model: string } | null>(null);
  const scan = useMutation({ mutationFn: () => discover(cidr) });
  const found = scan.data?.candidates ?? [];

  return (
    <Card shadow="sm" padding="lg" radius="md" withBorder mt="xl">
      <Stack gap="sm">
        <Group justify="space-between">
          <Title order={5}>Discover access points</Title>
          <Text size="xs" c="dimmed">
            pre-auth TLS fingerprint scan, no login
          </Text>
        </Group>
        <Group gap="xs" align="flex-end">
          <TextInput
            label="Subnet (CIDR)"
            placeholder="192.168.1.0/24"
            value={cidr}
            onChange={(e) => setCidr(e.currentTarget.value)}
            style={{ flexGrow: 1, maxWidth: 280 }}
          />
          <Button loading={scan.isPending} disabled={!cidr} onClick={() => scan.mutate()}>
            Scan
          </Button>
        </Group>
        {scan.isError && (
          <Text size="sm" c="red">
            {(scan.error as Error).message}
          </Text>
        )}
        {scan.isSuccess && found.length === 0 && (
          <Text size="sm" c="dimmed">
            No WAX access points found in {cidr}.
          </Text>
        )}
        {found.length > 0 && (
          <Table fz="sm">
            <Table.Tbody>
              {found.map((c) => (
                <Table.Tr key={c.ip}>
                  <Table.Td>{c.ip}</Table.Td>
                  <Table.Td>{c.model || "WAX (model unknown)"}</Table.Td>
                  <Table.Td align="right">
                    {c.known ? (
                      <Badge color="green" variant="light">
                        in config
                      </Badge>
                    ) : (
                      <Button
                        size="compact-xs"
                        onClick={() => setAddFor({ host: c.ip, model: c.model || "" })}
                      >
                        Add
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Stack>
      <DeviceFormModal
        mode="add"
        opened={!!addFor}
        onClose={() => setAddFor(null)}
        prefill={addFor ? { host: addFor.host, model: addFor.model } : undefined}
      />
    </Card>
  );
}

// DeviceActions: the per-card Edit and Remove controls. Removing only drops the
// device from config.yaml (its stored backups stay); it never touches the AP.
function DeviceActions({ device }: { device: Device }) {
  const qc = useQueryClient();
  const [editOpen, setEditOpen] = useState(false);
  const [removeOpen, setRemoveOpen] = useState(false);
  const remove = useMutation({
    mutationFn: () => removeDevice(device.name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices"] }),
  });
  return (
    <>
      <Group gap={4}>
        <Button size="compact-xs" variant="subtle" onClick={() => setEditOpen(true)}>
          Edit
        </Button>
        <Button
          size="compact-xs"
          variant="subtle"
          color="red"
          onClick={() => setRemoveOpen(true)}
        >
          Remove
        </Button>
      </Group>
      <DeviceFormModal
        mode="edit"
        editName={device.name}
        opened={editOpen}
        onClose={() => setEditOpen(false)}
      />
      <ConfirmModal
        opened={removeOpen}
        onClose={() => setRemoveOpen(false)}
        device={device.name}
        title={`Remove ${device.name}`}
        confirmLabel="Remove"
        color="red"
        busy={remove.isPending}
        onConfirm={() => {
          setRemoveOpen(false);
          remove.mutate();
        }}
      >
        <Text size="sm">
          This removes <b>{device.name}</b> from config.yaml so selfsight stops
          managing it. It does <b>not</b> touch the access point, and any config
          backups already saved on the server are kept.
        </Text>
      </ConfirmModal>
    </>
  );
}

const emptyForm: DeviceInput = {
  name: "",
  host: "",
  model: "",
  username: "admin",
  password: "",
};

// DeviceFormModal adds a new device or edits an existing one. It edits
// config.yaml on the server and, for an existing device, prefills from the
// stored config (never the password: leave it blank to keep the current one).
// "Test connection" logs into the AP with the typed credentials so you can
// confirm reachability before saving.
function DeviceFormModal({
  mode,
  opened,
  onClose,
  editName,
  prefill,
}: {
  mode: "add" | "edit";
  opened: boolean;
  onClose: () => void;
  editName?: string;
  prefill?: Partial<DeviceInput>;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<DeviceInput>({ ...emptyForm, ...prefill });
  const [hasPassword, setHasPassword] = useState(false);
  const [test, setTest] = useState<ConnectionTest | null>(null);

  // On open: reset for add, or load the stored config for edit.
  const config = useQuery({
    queryKey: ["device-config", editName],
    queryFn: () => fetchDeviceConfig(editName!),
    enabled: opened && mode === "edit" && !!editName,
    retry: false,
  });
  useEffect(() => {
    if (!opened) return;
    setTest(null);
    if (mode === "add") {
      setForm({ ...emptyForm, ...prefill });
      setHasPassword(false);
    } else if (config.data) {
      const d = config.data.device;
      setForm({ ...d, password: "" });
      setHasPassword(config.data.hasPassword);
    }
    // prefill is a fresh object each render; key off its contents.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened, mode, config.data, prefill?.host, prefill?.model]);

  const setField = (k: keyof DeviceInput, v: string) => setForm((f) => ({ ...f, [k]: v }));

  // The form edits connection settings only; a stored declared config rides
  // along untouched (it lives in `form.desired` from the config load).
  const save = useMutation({
    mutationFn: () =>
      mode === "add" ? addDevice({ ...form }) : updateDevice(editName!, { ...form }),
    onSuccess: () => {
      qc.invalidateQueries();
      onClose();
    },
  });
  const conn = useMutation({
    mutationFn: () =>
      testConnection({
        host: form.host,
        username: form.username,
        password: form.password,
        model: form.model,
        name: form.name,
      }),
    onSuccess: (res) => {
      setTest(res);
      // Adopt the AP's own name once we've reached it — but only if the user
      // hasn't already typed one, so a deliberate name is never overwritten.
      // The serial is always taken: it pins this entry to the unit we just
      // reached, and the server checks it before any future write.
      if (res.ok) {
        setForm((f) => ({
          ...f,
          ...(res.name && !f.name.trim() ? { name: res.name } : {}),
          ...(res.serial ? { serial: res.serial } : {}),
        }));
      }
    },
  });

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={mode === "add" ? "Add access point" : `Edit ${editName}`}
      centered
      size="lg"
    >
      <Stack gap="sm">
        <Group grow>
          <TextInput
            label="Name"
            placeholder="auto-fills from the AP on Test connection"
            value={form.name}
            onChange={(e) => setField("name", e.currentTarget.value)}
          />
          <TextInput
            label="Host / IP"
            placeholder="192.0.2.20"
            value={form.host}
            onChange={(e) => setField("host", e.currentTarget.value)}
          />
        </Group>
        <Group grow>
          <TextInput
            label="Model"
            placeholder="WAX610"
            value={form.model ?? ""}
            onChange={(e) => setField("model", e.currentTarget.value)}
          />
          <TextInput
            label="Username"
            value={form.username}
            onChange={(e) => setField("username", e.currentTarget.value)}
          />
        </Group>
        <PasswordInput
          label="Password"
          placeholder={hasPassword ? "leave blank to keep current" : "AP admin password"}
          value={form.password ?? ""}
          onChange={(e) => setField("password", e.currentTarget.value)}
        />

        <Group gap="xs">
          <Button
            size="xs"
            variant="light"
            loading={conn.isPending}
            disabled={!form.host}
            onClick={() => conn.mutate()}
          >
            Test connection
          </Button>
          {test &&
            (test.ok ? (
              <Text size="xs" c="green">
                reached {test.name || form.host}
                {test.firmware ? ` · ${test.firmware}` : ""}
                {test.standalone === false ? " · Insight-managed!" : ""}
              </Text>
            ) : (
              <Text size="xs" c="red">
                {test.error}
              </Text>
            ))}
          {conn.isError && (
            <Text size="xs" c="red">
              {(conn.error as Error).message}
            </Text>
          )}
        </Group>

        <Text size="xs" c="dimmed" mt="xs">
          Networks, radio settings, and what selfsight manages are all viewed
          and changed from the device's “All details” page.
        </Text>

        {save.isError && (
          <Text size="sm" c="red">
            {(save.error as Error).message}
          </Text>
        )}
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button
            loading={save.isPending}
            disabled={!form.name || !form.host || !form.username}
            onClick={() => save.mutate()}
          >
            {mode === "add" ? "Add device" : "Save"}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text size="sm" fw={500}>
        {value || "—"}
      </Text>
    </div>
  );
}
