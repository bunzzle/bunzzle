import type { Logger } from "../core/log.ts";
import type { NsMeasure } from "../dns/probe.ts";
import type { Server } from "../dns/resolver.ts";

const FAILURES = 3;
const MAX_LAG_SECONDS = 120;
const INTERVAL_MS = 60_000;
const RETRY_MS = 10_000;

export interface NsTargetView {
  ns: string;
  udp: boolean;
  tcp: boolean;
  serial: number | null;
  lagSeconds: number;
  failures: number;
  healthy: boolean;
  checkedAt: number | null;
}

export interface NsProbeDeps {
  targets: () => Promise<Server[]>;
  pushed: () => { serial: number; at: number } | null;
  measure: (server: Server) => Promise<NsMeasure>;
  raise: (kind: "ns.unhealthy" | "ns.healthy", data: Record<string, unknown>) => Promise<void>;
  log: Logger;
  now?: () => number;
}

export function nsProbe(deps: NsProbeDeps) {
  const now = deps.now ?? Date.now;
  const state = new Map<string, NsTargetView>();
  let checkedAt: number | null = null;

  const probe = async (server: Server, at: number): Promise<NsTargetView> => {
    const ns = server.host;
    const m = await deps.measure(server).catch(() => ({ udp: null, tcp: null, served: null }));
    const served = m.served;
    const before = state.get(ns);
    const udp = m.udp !== null && served !== null;
    const tcp = m.tcp !== null;
    const failures = udp && tcp ? 0 : (before?.failures ?? 0) + 1;
    const pushed = deps.pushed();
    const lagSeconds =
      pushed && (served === null || served < pushed.serial)
        ? Math.max(0, Math.round((at - pushed.at) / 1000))
        : 0;
    return {
      ns,
      udp,
      tcp,
      serial: served,
      lagSeconds,
      failures,
      healthy: failures < FAILURES && lagSeconds <= MAX_LAG_SECONDS,
      checkedAt: at,
    };
  };

  const record = async (view: NsTargetView) => {
    const before = state.get(view.ns);
    state.set(view.ns, view);
    const data = {
      ns: view.ns,
      udp: view.udp,
      tcp: view.tcp,
      serial: view.serial,
      lag_seconds: view.lagSeconds,
      failures: view.failures,
    };
    if (!view.healthy && (before?.healthy ?? true)) {
      deps.log.error("ns is unhealthy", data);
      await deps.raise("ns.unhealthy", data);
    } else if (view.healthy && before && !before.healthy) {
      deps.log.info("ns is healthy again", data);
      await deps.raise("ns.healthy", data);
    }
  };

  const tick = async () => {
    const at = now();
    checkedAt = at;
    let targets: Server[];
    try {
      targets = await deps.targets();
    } catch (err) {
      deps.log.warn("could not list the ns listeners", { error: (err as Error).message });
      for (const v of [...state.values()]) {
        const failures = v.failures + 1;
        await record({
          ...v,
          udp: false,
          tcp: false,
          failures,
          healthy: failures < FAILURES && v.lagSeconds <= MAX_LAG_SECONDS,
          checkedAt: at,
        });
      }
      return;
    }
    const seen = new Set<string>();
    for (const view of await Promise.all(targets.map((t) => probe(t, at)))) {
      seen.add(view.ns);
      await record(view);
    }
    for (const ns of state.keys()) if (!seen.has(ns)) state.delete(ns);
  };

  const poll = () => {
    const allUp = state.size > 0 && [...state.values()].every((v) => v.udp && v.tcp);
    const wait = allUp ? INTERVAL_MS : RETRY_MS;
    return checkedAt === null || now() - checkedAt >= wait ? tick() : Promise.resolve();
  };

  const view = (): NsTargetView[] => [...state.values()].sort((a, b) => a.ns.localeCompare(b.ns));

  const servesAtLeast = (serial: number): boolean =>
    state.size > 0 && view().every((v) => v.udp && v.tcp && (v.serial ?? 0) >= serial);

  return { tick, poll, view, servesAtLeast };
}
