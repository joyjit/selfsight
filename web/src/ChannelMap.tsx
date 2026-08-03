import {
  Badge,
  Button,
  Card,
  Group,
  Modal,
  Progress,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { useMutation, useQueries } from "@tanstack/react-query";
import { useState } from "react";
import {
  applyDeviceChange,
  fetchCachedStatus,
  fetchDeviceStatus,
  type Device,
  type DeviceStatus,
} from "./api";
import { useSettleStatus } from "./useSettleStatus";

// The API keys radios by short band name; the map labels them by frequency.
const BAND_KEY: Record<string, string> = {
  "2.4 GHz": "2g",
  "5 GHz": "5g",
  "6 GHz": "6g",
};

// One AP can be suggested a move on more than one band, so results are keyed by
// both band and device.
const moveKey = (band: string, device: string) => `${band}|${device}`;

interface MoveResult {
  applied: boolean;
  observed: string;
  error?: string;
}

// neighborColor grades OBSS (neighbour) airtime — how much of the channel is
// eaten by nearby networks we don't manage. High means a crowded channel worth
// avoiding even when our own APs aren't clashing.
function neighborColor(pct: number): string {
  if (pct >= 40) return "red";
  if (pct >= 20) return "orange";
  return "dimmed";
}

// ChannelMap is the fleet-wide view of the air: which AP sits on which
// channel, per band, with overlap warnings and a suggested non-colliding
// assignment. Read-only — applying a channel stays a per-AP guarded write
// from the device's All-details page. It sees only our own APs; the
// utilization column is the hint for everything else on the air (neighbours
// included).

interface RadioRow {
  device: string;
  channel: number | null; // null = unparseable ("auto", no data)
  rawChannel: string;
  width: string;
  util: string;
  neighbor: string; // OBSS: airtime used by OTHER (neighbour) networks, %
  neighborPct: number | null; // parsed neighbor %, null = no reading
  stations: number; // clients on this band — the optimizer's weight
  stale: boolean; // from the cached last reading, not a live read
}

const parseChannel = (s: string): number | null => {
  const n = parseInt(s, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
};

// Two 20 MHz channels on 2.4 GHz overlap when they are closer than 5 apart —
// the reason only 1/6/11 coexist cleanly. On 5 GHz, channels interfere when
// they fall in the same 80 MHz block (36–48, 52–64, 100–112, …), which also
// covers same-channel sharing.
const fiveGhzBlock = (ch: number): number => Math.floor((ch - 36) / 16);

export function channelsOverlap(band: string, a: number, b: number): boolean {
  if (band.startsWith("2.4")) {
    return Math.abs(a - b) < 5;
  }
  return fiveGhzBlock(a) === fiveGhzBlock(b);
}

// Preferred assignments per band: the classic 1/6/11 on 2.4 GHz; on 5 GHz one
// channel per 80 MHz block, favouring the non-radar-shared ends first.
const preferred: Record<string, number[]> = {
  "2.4 GHz": [1, 6, 11],
  "5 GHz": [36, 52, 149, 100, 116, 132],
  "6 GHz": [37, 53, 69, 85, 101, 117],
};

// The largest width the radio is set to run, in MHz, read out of the label the
// AP reports ("20/40 MHz" -> 40, "20/40/80 MHz" -> 80). Unknown -> 20.
export function maxWidthMHz(width: string): number {
  const nums = (width.match(/\d+/g) ?? []).map(Number);
  return nums.length > 0 ? Math.max(...nums) : 20;
}

// Can this radio actually tune to this channel at its current width? On 2.4 GHz
// a 40 MHz channel pairs the primary with a second 20 MHz channel four above
// it, and that pair must still fit under channel 11 (the top of the US 2.4 GHz
// band) — so at 40 MHz the primary can be at most 7. That is why channel 11
// never comes up at 40 MHz: the AP has nowhere to put the upper half, so it
// silently stays put. At 20 MHz every channel stands alone. On 5/6 GHz the
// preferred channels are already valid block starts, so nothing is excluded.
export function channelRunsAt(band: string, channel: number, width: number): boolean {
  if (band.startsWith("2.4") && width >= 40) {
    return channel + 4 <= 11;
  }
  return true;
}

// suggestAssignment proposes a non-overlapping channel per AP, moving as few
// APs as possible: whoever already holds a preferred channel (no conflict)
// keeps it; each remaining AP takes the first preferred channel that is both
// still clean AND one its radio can actually run at its current width. An AP
// that has no clean, runnable channel left is not moved at all — shuffling it
// onto another busy channel would not reduce a single overlap. When that
// happens the band is genuinely out of room (see bandAnalysis's note).
export function suggestAssignment(band: string, rows: RadioRow[]): Map<string, number> {
  const prefs = preferred[band] ?? [];
  const out = new Map<string, number>();
  if (prefs.length === 0) {
    return out;
  }
  const taken = new Set<number>();
  const movers: RadioRow[] = [];
  const sorted = [...rows].sort((a, b) => a.device.localeCompare(b.device));
  for (const r of sorted) {
    const keep =
      r.channel !== null &&
      prefs.includes(r.channel) &&
      ![...taken].some((t) => channelsOverlap(band, t, r.channel!));
    if (keep) {
      taken.add(r.channel!);
      out.set(r.device, r.channel!);
    } else {
      movers.push(r);
    }
  }
  for (const r of movers) {
    const width = maxWidthMHz(r.width);
    const pick = prefs.find(
      (p) =>
        channelRunsAt(band, p, width) &&
        ![...taken].some((t) => channelsOverlap(band, t, p)),
    );
    if (pick !== undefined) {
      taken.add(pick);
      out.set(r.device, pick);
    }
  }
  return out;
}

// One suggested change: move this AP off its current (overlapping) channel
// onto a clean one, optionally narrowing the radio to 20 MHz at the same time
// (the only way to fit 1/6/11 when the band is crowded at 40 MHz).
export interface ChannelMove {
  device: string;
  from: number | null;
  to: number;
  narrow?: boolean; // also set channel width to 20 MHz
}

// bandAnalysis: every overlapping pair, and (only when something overlaps) the
// concrete list of channel moves that would clear the conflicts.
export function bandAnalysis(band: string, rows: RadioRow[]) {
  const usable = rows.filter((r) => r.channel !== null);
  const conflicts: string[] = [];
  const conflicted = new Set<string>();
  for (let i = 0; i < usable.length; i++) {
    for (let j = i + 1; j < usable.length; j++) {
      const a = usable[i];
      const b = usable[j];
      if (!channelsOverlap(band, a.channel!, b.channel!)) {
        continue;
      }
      conflicted.add(a.device);
      conflicted.add(b.device);
      conflicts.push(
        a.channel === b.channel
          ? `${a.device} and ${b.device} share channel ${a.channel}`
          : `${a.device} (ch ${a.channel}) and ${b.device} (ch ${b.channel}) overlap`,
      );
    }
  }
  const moves: ChannelMove[] = [];
  let note = "";
  if (conflicts.length > 0) {
    const plan = suggestAssignment(band, usable);
    for (const r of usable) {
      const to = plan.get(r.device);
      if (to !== undefined && to !== r.channel) {
        moves.push({ device: r.device, from: r.channel, to });
      }
    }
    // Would overlaps still remain once the plan is applied? (Each AP ends up on
    // its planned channel, or stays put if the plan left it alone.) If so the
    // band is out of clean channels — on 2.4 GHz that is almost always because
    // the radios are running 40 MHz, which halves how many fit.
    const finals = usable.map((r) => plan.get(r.device) ?? r.channel!);
    if (hasOverlap(band, finals)) {
      const wide = band.startsWith("2.4") && usable.some((r) => maxWidthMHz(r.width) >= 40);
      if (wide) {
        // The only real fix: narrow the whole 2.4 GHz band to 20 MHz, which
        // makes 1/6/11 fit. Plan channels as if every radio were already 20 MHz
        // (all preferred channels become runnable), and mark each radio that is
        // wider than 20 to be narrowed. This replaces the channel-only moves —
        // shuffling channels at 40 MHz can't separate three APs.
        const narrowRows = usable.map((r) => ({ ...r, width: "20 MHz" }));
        const plan20 = suggestAssignment(band, narrowRows);
        const narrowed: ChannelMove[] = [];
        for (const r of usable) {
          const to = plan20.get(r.device);
          if (to === undefined) continue;
          const narrow = maxWidthMHz(r.width) > 20;
          if (to !== r.channel || narrow) {
            narrowed.push({ device: r.device, from: r.channel, to, narrow });
          }
        }
        moves.length = 0;
        moves.push(...narrowed);
      } else {
        note = "not enough clean channels to separate every AP on this band.";
      }
    }
  }
  return { conflicts, conflicted, moves, note };
}

// hasOverlap reports whether any two channels in the list overlap on the band.
function hasOverlap(band: string, channels: number[]): boolean {
  for (let i = 0; i < channels.length; i++) {
    for (let j = i + 1; j < channels.length; j++) {
      if (channelsOverlap(band, channels[i], channels[j])) {
        return true;
      }
    }
  }
  return false;
}

// TWO_4 is the 2.4 GHz band — the only band the congestion visualizer and the
// assignment optimizer act on (its usable channels are just 1/6/11, and a fleet
// spread across them already measures all three, so no scan is needed).
const TWO_4 = "2.4 GHz";

// ChannelLoad is neighbour congestion measured on one usable 2.4 GHz channel, by
// whichever AP currently sits there — null when no AP occupies it, so the UI can
// say "unmeasured" instead of pretending the channel is clear.
export interface ChannelLoad {
  channel: number;
  neighbor: number | null; // OBSS %, null = unmeasured (no AP on it)
  device: string | null;
}

// congestion24 reports neighbour congestion for each usable 2.4 GHz channel
// (1/6/11), read from the AP that sits on it.
export function congestion24(rows: RadioRow[]): ChannelLoad[] {
  return (preferred[TWO_4] ?? []).map((channel) => {
    const ap = rows.find((r) => r.channel === channel);
    return {
      channel,
      neighbor: ap ? ap.neighborPct : null,
      device: ap ? ap.device : null,
    };
  });
}

// Rebalance is the optimizer's verdict for the 2.4 GHz band:
//  - "swap": a client-weighted channel swap that meaningfully lowers interference
//  - "optimal": the APs are already assigned as well as 1/6/11 allows (so the
//    absence of a suggestion is explained, not silent)
//  - null: the optimizer doesn't apply (overlap to fix first, no clients, or a
//    missing reading)
export type Rebalance =
  | { kind: "swap"; moves: ChannelMove[]; before: number; after: number }
  | { kind: "optimal"; busiest: string; channel: number }
  | null;

// suggestReassignment weighs each 2.4 GHz AP by its client count and asks
// whether the AP with the most clients is on the least-congested channel. A
// channel's congestion comes from the neighbors on it, not from which of our
// APs sits there — so a swap keeps each channel's load and just moves OUR
// clients onto better air. Optimal pairing is heaviest AP -> least-congested
// channel (rearrangement inequality).
export function suggestReassignment(rows: RadioRow[]): Rebalance {
  const usable = preferred[TWO_4] ?? [];
  const aps = rows.filter((r) => r.channel !== null && usable.includes(r.channel));
  if (aps.length < 2) {
    return null;
  }
  const channels = aps.map((a) => a.channel!);
  if (new Set(channels).size !== channels.length) {
    return null; // two APs share a channel — that's the overlap fix's job
  }
  if (aps.some((a) => a.neighborPct === null)) {
    return null; // missing a reading — can't compare honestly
  }
  if (aps.reduce((s, a) => s + a.stations, 0) === 0) {
    return null; // no clients on the band — nothing to optimise for
  }

  const load = new Map<number, number>();
  for (const a of aps) {
    load.set(a.channel!, a.neighborPct!);
  }
  const weighted = (assign: Map<string, number>) =>
    aps.reduce((s, a) => s + a.stations * load.get(assign.get(a.device)!)!, 0);

  const current = new Map(aps.map((a) => [a.device, a.channel!] as const));
  const heaviestFirst = [...aps].sort((a, b) => b.stations - a.stations);
  const cleanestFirst = [...channels].sort((x, y) => load.get(x)! - load.get(y)!);
  const optimal = new Map<string, number>();
  heaviestFirst.forEach((a, i) => optimal.set(a.device, cleanestFirst[i]));

  const before = weighted(current);
  const after = weighted(optimal);
  const busiest = heaviestFirst[0];
  // Suggest a swap only when it clearly helps: a real drop of at least ~15%.
  // Otherwise the current assignment is already as good as it gets.
  if (before - after <= 0 || before - after < 0.15 * before) {
    return { kind: "optimal", busiest: busiest.device, channel: busiest.channel! };
  }

  const moves: ChannelMove[] = [];
  for (const a of aps) {
    const to = optimal.get(a.device)!;
    if (to !== a.channel) {
      moves.push({ device: a.device, from: a.channel, to });
    }
  }
  return moves.length > 0
    ? { kind: "swap", moves, before, after }
    : { kind: "optimal", busiest: busiest.device, channel: busiest.channel! };
}

function rowsFor(band: string, devices: Device[], statuses: (DeviceStatus | undefined)[], stale: boolean[]): RadioRow[] {
  const rows: RadioRow[] = [];
  devices.forEach((d, i) => {
    const st = statuses[i];
    if (!st) {
      return;
    }
    for (const r of st.system.radios ?? []) {
      if (r.band !== band) {
        continue;
      }
      const nb = parseInt(r.obssUtil ?? "", 10);
      rows.push({
        device: d.name,
        channel: parseChannel(r.channel),
        rawChannel: r.channel || "—",
        width: r.channelWidth || "—",
        util: r.channelUtil || "—",
        neighbor: r.obssUtil ?? "",
        neighborPct: Number.isFinite(nb) ? nb : null,
        stations: r.stations ?? 0,
        stale: stale[i],
      });
    }
  });
  return rows;
}

// barColor grades a congestion bar green/orange/red (green = clear). Distinct
// from neighborColor, which dims low values for the table.
function barColor(pct: number): string {
  if (pct >= 40) return "red";
  if (pct >= 20) return "orange";
  return "green";
}

// TwoGhzCongestion visualizes neighbour congestion on the three usable 2.4 GHz
// channels (1/6/11), measured by whichever AP sits on each. A channel no AP
// occupies is honestly marked "unmeasured" — we only know a channel's load if
// one of our radios is listening on it. The least-congested measured channel is
// flagged, which is exactly what the rebalance suggestion acts on.
function TwoGhzCongestion({ rows }: { rows: RadioRow[] }) {
  const loads = congestion24(rows);
  const measured = loads.filter((l) => l.neighbor !== null);
  if (measured.length === 0) {
    return null;
  }
  const cleanest = Math.min(...measured.map((l) => l.neighbor!));
  return (
    <Stack gap={2} mt={4}>
      <Text size="xs" fw={600}>
        Neighbor congestion by channel
      </Text>
      {loads.map((l) => (
        <Group key={l.channel} gap="xs" wrap="nowrap">
          <Text size="xs" w={30}>
            ch {l.channel}
          </Text>
          {l.neighbor === null ? (
            <Text size="xs" c="dimmed">
              unmeasured — no AP on this channel
            </Text>
          ) : (
            <>
              <Progress value={l.neighbor} color={barColor(l.neighbor)} w={110} size="md" />
              <Text
                size="xs"
                c={barColor(l.neighbor)}
                fw={l.neighbor === cleanest ? 700 : 400}
                w={90}
              >
                {l.neighbor}%{l.neighbor === cleanest ? " · cleanest" : ""}
              </Text>
              {l.device && (
                <Text size="xs" c="dimmed">
                  {l.device}
                </Text>
              )}
            </>
          )}
        </Group>
      ))}
      <Text size="xs" c="dimmed" mt={2}>
        Only channels 1, 6 and 11 don't overlap on 2.4 GHz — any other channel
        overlaps two of these and would interfere more, so they aren't options
        (and can't be measured, since no radio sits on them). High congestion
        here is your neighbors' networks, which you can't change: the levers are
        putting your busiest AP on the cleanest channel (below) and moving
        devices to 5 GHz.
      </Text>
    </Stack>
  );
}

export function ChannelMap({ devices }: { devices: Device[] }) {
  // Same query keys as the device cards, so this panel shares their cache and
  // never causes an extra read of any AP.
  const live = useQueries({
    queries: devices.map((d) => ({
      queryKey: ["status", d.name],
      queryFn: () => fetchDeviceStatus(d.name),
      retry: false,
    })),
  });
  const cached = useQueries({
    queries: devices.map((d) => ({
      queryKey: ["status-cached", d.name],
      queryFn: () => fetchCachedStatus(d.name),
      retry: false,
      staleTime: Infinity,
    })),
  });
  const statuses = devices.map((_, i) => live[i].data ?? cached[i].data?.status);
  const stale = devices.map((_, i) => !live[i].data && !!cached[i].data?.status);
  const missing = devices.filter((_, i) => !statuses[i]).map((d) => d.name);

  // Applying a suggested move is a guarded per-AP write: confirm first, then
  // hand it to the same backup-and-read-back pipeline every write goes through.
  const settle = useSettleStatus();
  const [confirm, setConfirm] = useState<(ChannelMove & { band: string }) | null>(
    null,
  );
  const [results, setResults] = useState<Record<string, MoveResult>>({});
  const apply = useMutation({
    mutationFn: (m: ChannelMove & { band: string }) =>
      applyDeviceChange(m.device, {
        radio: {
          band: BAND_KEY[m.band],
          channel: String(m.to),
          ...(m.narrow ? { width: "20" } : {}),
        },
      }),
    onSuccess: (resp, m) => {
      const r = resp.results?.[0];
      setResults((prev) => ({
        ...prev,
        [moveKey(m.band, m.device)]: {
          applied: !!r?.applied,
          observed: r?.observed ?? "",
          error: resp.error,
        },
      }));
      // The radio re-tunes over tens of seconds — poll until the map settles.
      settle(m.device);
    },
    onError: (err, m) => {
      setResults((prev) => ({
        ...prev,
        [moveKey(m.band, m.device)]: {
          applied: false,
          observed: "",
          error: err instanceof Error ? err.message : "failed",
        },
      }));
    },
  });

  // One suggested move: the label, the guarded Apply button (gone once it has
  // succeeded), and the result. Shared by the overlap/narrow fixes and the
  // 2.4 GHz rebalance so they look and behave identically.
  const moveRow = (band: string, m: ChannelMove) => {
    const res = results[moveKey(band, m.device)];
    const inFlight =
      apply.isPending &&
      apply.variables?.device === m.device &&
      apply.variables?.band === band;
    return (
      <Group key={m.device} gap="xs" wrap="nowrap">
        <Text size="xs">
          {m.device}:{" "}
          {m.from !== m.to ? `ch ${m.from ?? "auto"} → ${m.to}` : `ch ${m.to}`}
          {m.narrow ? ", narrow to 20 MHz" : ""}
        </Text>
        {!res?.applied && (
          <Button
            size="compact-xs"
            variant="light"
            loading={inFlight}
            disabled={apply.isPending}
            onClick={() => setConfirm({ band, ...m })}
          >
            Apply fix
          </Button>
        )}
        {res &&
          (res.error ? (
            <Text size="xs" c="red">
              failed: {res.error}
            </Text>
          ) : res.applied ? (
            <Badge size="xs" color="green" variant="light">
              now on ch {m.to}
              {m.narrow ? ", 20 MHz" : ""}
            </Badge>
          ) : (
            <Text size="xs" c="orange">
              didn't take — AP still on{" "}
              {res.observed.replace(/wlan\d+=/g, "") || "the old channel"}
            </Text>
          ))}
      </Group>
    );
  };

  const bands = ["2.4 GHz", "5 GHz", "6 GHz"]
    .map((band) => ({ band, rows: rowsFor(band, devices, statuses, stale) }))
    .filter(({ rows }) => rows.length > 0);
  if (bands.length === 0) {
    return null;
  }

  return (
    <Card shadow="sm" padding="lg" radius="md" withBorder mt="md">
      <Stack gap="sm">
        <Group justify="space-between">
          <Title order={5}>Channels across the fleet</Title>
          <Text size="xs" c="dimmed" maw={360} ta="right">
            Utilization is total airtime busy; Neighbors is the share from nearby
            networks you don't manage — a high Neighbors % is a crowded channel
            worth avoiding even with no overlap of your own.
          </Text>
        </Group>
        {bands.map(({ band, rows }) => {
          const { conflicts, conflicted, moves, note } = bandAnalysis(band, rows);
          return (
            <Stack key={band} gap={4}>
              <Group gap="xs">
                <Text fw={600} size="sm">
                  {band}
                </Text>
                {conflicts.length === 0 ? (
                  <Badge color="green" variant="dot" size="sm">
                    no overlap
                  </Badge>
                ) : (
                  <Badge color="orange" variant="light" size="sm">
                    {conflicts.length} overlap{conflicts.length > 1 ? "s" : ""}
                  </Badge>
                )}
              </Group>
              <Table.ScrollContainer minWidth={0} type="native">
                <Table fz="xs" verticalSpacing={2} striped>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Access point</Table.Th>
                      <Table.Th>Channel</Table.Th>
                      <Table.Th>Width</Table.Th>
                      <Table.Th>Utilization</Table.Th>
                      <Table.Th>Neighbors</Table.Th>
                      <Table.Th></Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {rows.map((r) => (
                      <Table.Tr key={r.device}>
                        <Table.Td>{r.device}</Table.Td>
                        <Table.Td>{r.rawChannel}</Table.Td>
                        <Table.Td>{r.width}</Table.Td>
                        <Table.Td>{r.util}</Table.Td>
                        <Table.Td>
                          {r.neighbor === "" ? (
                            <Text size="xs" c="dimmed">
                              —
                            </Text>
                          ) : (
                            <Text
                              size="xs"
                              fw={neighborColor(parseInt(r.neighbor, 10) || 0) !== "dimmed" ? 600 : 400}
                              c={neighborColor(parseInt(r.neighbor, 10) || 0)}
                            >
                              {r.neighbor}%
                            </Text>
                          )}
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4} wrap="nowrap">
                            {conflicted.has(r.device) && (
                              <Badge size="xs" color="orange" variant="light">
                                overlaps
                              </Badge>
                            )}
                            {r.stale && (
                              <Badge size="xs" color="gray" variant="light">
                                last known
                              </Badge>
                            )}
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
              {conflicts.map((c) => (
                <Text key={c} size="xs" c="orange">
                  {c}
                </Text>
              ))}
              {moves.length > 0 && (
                <Stack gap={2} mt={2}>
                  <Text size="xs" c="blue">
                    {moves.some((m) => m.narrow)
                      ? "Suggested fix — narrow 2.4 GHz to 20 MHz so 1/6/11 all fit (one AP at a time, a backup taken first):"
                      : "Suggested fix — one AP at a time, a backup taken first:"}
                  </Text>
                  {moves.map((m) => moveRow(band, m))}
                </Stack>
              )}
              {note && (
                <Text size="xs" c="dimmed">
                  {note}
                </Text>
              )}
              {band === TWO_4 && <TwoGhzCongestion rows={rows} />}
              {band === TWO_4 &&
                conflicts.length === 0 &&
                (() => {
                  const rb = suggestReassignment(rows);
                  if (!rb) {
                    return null;
                  }
                  if (rb.kind === "optimal") {
                    return (
                      <Text size="xs" c="dimmed" mt={2}>
                        Channel assignment is already optimal — {rb.busiest} has
                        the most 2.4 GHz clients and is on ch {rb.channel}, the
                        cleanest of 1/6/11. No swap would help.
                      </Text>
                    );
                  }
                  return (
                    <Stack gap={2} mt={2}>
                      <Text size="xs" c="blue">
                        Rebalance — no channels overlap, but a busier AP is on a
                        more crowded channel than a quieter one. Swap them so your
                        most-used AP gets the cleaner air (one AP at a time,
                        backup first):
                      </Text>
                      {rb.moves.map((m) => moveRow(band, m))}
                    </Stack>
                  );
                })()}
            </Stack>
          );
        })}
        {missing.length > 0 && (
          <Text size="xs" c="dimmed">
            no reading yet from: {missing.join(", ")}
          </Text>
        )}
      </Stack>
      <Modal
        opened={confirm !== null}
        onClose={() => setConfirm(null)}
        title="Change channel"
        centered
      >
        {confirm && (
          <Stack gap="sm">
            <Text size="sm">
              Set the {confirm.band} radio on <b>{confirm.device}</b> from
              channel {confirm.from ?? "auto"} to <b>{confirm.to}</b>
              {confirm.narrow ? (
                <>
                  {" "}
                  and narrow it to <b>20 MHz</b>
                </>
              ) : null}
              .
            </Text>
            <Text size="xs" c="dimmed">
              {confirm.narrow
                ? "Narrowing to 20 MHz briefly drops the 2.4 GHz clients on this AP while the radio restarts (a few seconds), then they reconnect. "
                : ""}
              selfsight takes a fresh backup first, writes the change, then reads
              the AP back to confirm the radio actually moved. No other access
              point is touched.
            </Text>
            <Group justify="flex-end" gap="xs">
              <Button variant="default" size="xs" onClick={() => setConfirm(null)}>
                Cancel
              </Button>
              <Button
                size="xs"
                onClick={() => {
                  apply.mutate(confirm);
                  setConfirm(null);
                }}
              >
                Apply fix
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
