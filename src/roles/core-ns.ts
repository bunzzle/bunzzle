import type { Logger } from "../core/log.ts";
import type { NsMeasure } from "../dns/probe.ts";
import type { Server } from "../dns/resolver.ts";

const FAILURES = 3;
const MAX_LAG_SECONDS = 120;
const INTERVAL_MS = 60_000;
const RETRY_MS = 10_000;
const RECOVER_MS = 10 * 60_000;
const MIN_UNHEALTHY_MS = 60 * 60_000;

export interface NsTargetView {
  ns: string;
  udp: boolean;
  tcp: boolean;
  serial: number | null;
  lagSeconds: number;
  failures: number;
  healthy: boolean;
  checkedAt: number | null;
  goodSince: number | null;
  unhealthySince: number | null;
}

type Reading = Pick<NsTargetView, "ns" | "udp" | "tcp" | "serial" | "lagSeconds" | "failures"> & {
  checkedAt: number;
};

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

  const probe = async (server: Server, at: number): Promise<Reading> => {
    const ns = server.host;
    const m = await deps.measure(server).catch(() => ({ udp: null, tcp: null, served: null }));
    const served = m.served;
    const udp = m.udp !== null && served !== null;
    const tcp = m.tcp !== null;
    const pushed = deps.pushed();
    const lagSeconds =
      pushed && (served === null || served < pushed.serial)
        ? Math.max(0, Math.round((at - pushed.at) / 1000))
        : 0;
    const failures = udp && tcp ? 0 : (state.get(ns)?.failures ?? 0) + 1;
    return { ns, udp, tcp, serial: served, lagSeconds, failures, checkedAt: at };
  };

  const record = async (r: Reading) => {
    const before = state.get(r.ns);
    const at = r.checkedAt;
    const good = r.udp && r.tcp && r.lagSeconds <= MAX_LAG_SECONDS;
    const goodSince = good ? (before?.goodSince ?? at) : null;
    const bad = r.failures >= FAILURES || r.lagSeconds > MAX_LAG_SECONDS;
    const healthy =
      before && !before.healthy
        ? goodSince !== null &&
          at - goodSince >= RECOVER_MS &&
          at - (before.unhealthySince ?? at) >= MIN_UNHEALTHY_MS
        : !bad;
    const view: NsTargetView = {
      ...r,
      healthy,
      goodSince,
      unhealthySince: healthy ? null : (before?.unhealthySince ?? at),
    };
    state.set(r.ns, view);
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
        await record({ ...v, udp: false, tcp: false, failures: v.failures + 1, checkedAt: at });
      }
      return;
    }
    const seen = new Set<string>();
    for (const reading of await Promise.all(targets.map((t) => probe(t, at)))) {
      seen.add(reading.ns);
      await record(reading);
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
