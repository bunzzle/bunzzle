import type { Logger } from "../core/log.ts";
import {
  type DelegatedDomain,
  slotKeys,
  zoneRecords,
  zoneWithSerial,
} from "../domains/delegated.ts";
import type { PublicDkimKey } from "../domains/domains.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";

export interface ZonePublisherDeps {
  ns: Pick<RpcClient, "call">;
  zone: string;
  ttl: number;
  sourceIps: string[];
  inboundHost: string | null;
  domains: () => Promise<DelegatedDomain[]> | DelegatedDomain[];
  log: Logger;
  now?: () => number;
}

const stats = b.object({ serial: b.number().int().nullable() });

export function zonePublisher(deps: ZonePublisherDeps) {
  const now = deps.now ?? Date.now;
  let pushed: { serial: number; content: string } | null = null;
  let failing = false;

  const tick = async (): Promise<number | null> => {
    try {
      const records = zoneRecords({
        zone: deps.zone,
        ttl: deps.ttl,
        sourceIps: deps.sourceIps,
        inboundHost: deps.inboundHost,
        domains: await deps.domains(),
      });
      const content = JSON.stringify(records);
      const current = await deps.ns.call("stats", {}, { timeoutMs: 5_000, result: stats });
      if (pushed && pushed.content === content && current.serial === pushed.serial) {
        return pushed.serial;
      }
      const serial = Math.max(
        Math.floor(now() / 1000),
        (current.serial ?? 0) + 1,
        (pushed?.serial ?? 0) + 1,
      );
      await deps.ns.call("zone", zoneWithSerial(deps.zone, deps.ttl, records, serial), {
        timeoutMs: 10_000,
      });
      pushed = { serial, content };
      if (failing) deps.log.info("zone pushed to ns again", { serial });
      failing = false;
      return serial;
    } catch (err) {
      if (!failing)
        deps.log.warn("could not push the zone to ns", { error: (err as Error).message });
      failing = true;
      return null;
    }
  };

  return { tick };
}

const KEYS_MS = 300_000;

export function delegatedDomains(deps: {
  names: () => string[];
  keys: (domain: string) => Promise<PublicDkimKey[]>;
  log: Logger;
  now?: () => number;
}): () => Promise<DelegatedDomain[]> {
  const now = deps.now ?? Date.now;
  const cache = new Map<string, { at: number; keys: DelegatedDomain["keys"] }>();
  return async () => {
    const names = deps.names();
    const live = new Set(names);
    for (const name of cache.keys()) if (!live.has(name)) cache.delete(name);
    const out: DelegatedDomain[] = [];
    for (const name of names) {
      let hit = cache.get(name);
      if (!hit || now() - hit.at >= KEYS_MS) {
        try {
          const keys = slotKeys(await deps.keys(name));
          if (!keys)
            deps.log.warn("DKIM keys of a delegated domain are not in slots", { domain: name });
          hit = { at: now(), keys: keys ?? {} };
          cache.set(name, hit);
        } catch (err) {
          if (!hit) throw err;
        }
      }
      out.push({ name, keys: hit.keys });
    }
    return out;
  };
}
