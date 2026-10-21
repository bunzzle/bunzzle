import type { Destination } from "../dns/mx.ts";
import type { DeliveryTransport } from "./transport.ts";

export interface LookupCacheOptions {
  maxEntries?: number;
  ttlMs?: number;
  now?: () => number;
}

export function cachingLookups(
  inner: DeliveryTransport,
  o: LookupCacheOptions = {},
): DeliveryTransport {
  const maxEntries = o.maxEntries ?? 10_000;
  const ttlMs = o.ttlMs ?? 5_000;
  const now = o.now ?? Date.now;
  const answers = new Map<string, { at: number; destination: Promise<Destination> }>();
  return {
    ...inner,
    lookup(domain) {
      const at = now();
      const hit = answers.get(domain);
      if (hit && at - hit.at < ttlMs) return hit.destination;
      answers.delete(domain);
      if (answers.size >= maxEntries) answers.delete(answers.keys().next().value as string);
      const destination = inner.lookup(domain);
      answers.set(domain, { at, destination });
      destination.catch(() => {
        if (answers.get(domain)?.destination === destination) answers.delete(domain);
      });
      return destination;
    },
  };
}
