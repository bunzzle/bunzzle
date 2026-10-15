import type { Clock } from "../core/clock.ts";
import { systemClock } from "../core/clock.ts";
import type { DnsAnswer, Resolver } from "./resolver.ts";
import { Rcode } from "./wire.ts";

export interface CacheOptions {
  clock?: Clock;
  minTtl?: number;
  maxTtl?: number;
  maxNegativeTtl?: number;
  failureTtl?: number;
  maxEntries?: number;
}

export function cachingResolver(inner: Resolver, opts: CacheOptions = {}): Resolver {
  const clock = opts.clock ?? systemClock;
  const minTtl = opts.minTtl ?? 30;
  const maxTtl = opts.maxTtl ?? 3600;
  const maxNegativeTtl = opts.maxNegativeTtl ?? 300;
  const failureTtl = opts.failureTtl ?? 5;
  const maxEntries = opts.maxEntries ?? 50_000;
  const entries = new Map<string, { answer: DnsAnswer; expires: number }>();
  const inflight = new Map<string, Promise<DnsAnswer>>();

  const lifetime = (a: DnsAnswer): number => {
    if (a.rcode === Rcode.SERVFAIL || a.rcode === Rcode.REFUSED) return failureTtl;
    if (a.records.length === 0) return Math.max(minTtl, Math.min(a.ttl, maxNegativeTtl));
    return Math.max(minTtl, Math.min(a.ttl, maxTtl));
  };

  return {
    query(name, type) {
      const key = `${type} ${name.toLowerCase()}`;
      const hit = entries.get(key);
      if (hit && hit.expires > clock.now()) return Promise.resolve(hit.answer);
      if (hit) entries.delete(key);
      const pending = inflight.get(key);
      if (pending) return pending;
      const p = inner
        .query(name, type)
        .then((answer) => {
          if (entries.size >= maxEntries) {
            const oldest = entries.keys().next();
            if (!oldest.done) entries.delete(oldest.value);
          }
          entries.set(key, { answer, expires: clock.now() + lifetime(answer) * 1000 });
          return answer;
        })
        .finally(() => inflight.delete(key));
      inflight.set(key, p);
      return p;
    },
  };
}
