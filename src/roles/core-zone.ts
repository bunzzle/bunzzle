import type { Logger } from "../core/log.ts";
import {
  type DelegatedDomain,
  slotKeys,
  zoneLabel,
  zoneRecords,
  zoneWithSerial,
} from "../domains/delegated.ts";
import { dkimValue, type PublicDkimKey } from "../domains/domains.ts";
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
  let pushed: {
    serial: number;
    at: number;
    content: string;
    records: ReturnType<typeof zoneRecords>;
  } | null = null;
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
      pushed = { serial, at: now(), content, records };
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

  const holds = (domain: string, keys: PublicDkimKey[]): boolean => {
    const owner = `${zoneLabel(domain)}.${deps.zone}`;
    return keys.every((k) =>
      pushed?.records.some((r) => r.name === `${k.selector}.${owner}` && r.value === dkimValue(k)),
    );
  };

  return {
    tick,
    holds,
    pushed: () => (pushed ? { serial: pushed.serial, at: pushed.at } : null),
  };
}

const KEYS_MS = 300_000;

export function delegatedDomains(deps: {
  names: () => string[];
  keys: (domain: string) => Promise<PublicDkimKey[]>;
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
          hit = { at: now(), keys: slotKeys(await deps.keys(name)) };
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
