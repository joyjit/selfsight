import { useCallback, useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";

// After a write, an AP's reported state lags — a radio re-tunes for tens of
// seconds — so a single refetch can still read the old value (and the status
// query does not retry). settle() refetches a device's status on a bounded
// window (every 8s for ~2 min) so the card, the drawer, and the channel map all
// converge on the settled state without a manual page reload. It polls only
// after a change; the dashboard is otherwise read on demand, never on a timer.
export function useSettleStatus() {
  const qc = useQueryClient();
  const timers = useRef<ReturnType<typeof setInterval>[]>([]);
  useEffect(
    () => () => {
      for (const id of timers.current) clearInterval(id);
      timers.current = [];
    },
    [],
  );
  return useCallback(
    (name: string) => {
      const refresh = () => {
        qc.invalidateQueries({ queryKey: ["status", name] });
        qc.invalidateQueries({ queryKey: ["drift", name] });
      };
      refresh();
      let ticks = 0;
      const id = setInterval(() => {
        refresh();
        if (++ticks >= 15) {
          clearInterval(id);
          timers.current = timers.current.filter((t) => t !== id);
        }
      }, 8_000);
      timers.current.push(id);
    },
    [qc],
  );
}
