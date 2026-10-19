import { type Family, forbiddenReason, sameAddress } from "./ip.ts";
import { DnsError, type Resolver } from "./resolver.ts";
import { DnsWireError, normalizeName, Rcode } from "./wire.ts";

export interface Target {
  host: string;
  preference: number;
  address: string;
  family: Family;
}

export interface Skipped {
  host: string;
  address: string;
  reason: string;
}

export type Destination =
  | {
      kind: "targets";
      domain: string;
      mxHosts: string[];
      implicit: boolean;
      authenticated: boolean;
      canonical?: string;
      targets: Target[];
      skipped: Skipped[];
    }
  | { kind: "fail"; domain: string; code: string; reason: string }
  | { kind: "defer"; domain: string; code: "nxdomain" | "dns-temporary"; reason: string };

export interface LookupOptions {
  resolver: Resolver;
  families?: Family[];
  maxAddresses?: number;
  allowPrivate?: boolean;
  ownAddresses?: string[];
  random?: () => number;
}

interface MxHost {
  host: string;
  preference: number;
}

function shuffleEqual(hosts: MxHost[], random: () => number): MxHost[] {
  const sorted = hosts.map((h) => ({ h, k: random() }));
  sorted.sort((a, b) => a.h.preference - b.h.preference || a.k - b.k);
  return sorted.map((x) => x.h);
}

function interleave<T>(a: T[], b: T[]): T[] {
  const out: T[] = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (i < a.length) out.push(a[i] as T);
    if (i < b.length) out.push(b[i] as T);
  }
  return out;
}

export async function lookupDestination(
  rawDomain: string,
  opts: LookupOptions,
): Promise<Destination> {
  const families = opts.families ?? [4];
  const maxAddresses = opts.maxAddresses ?? 5;
  const random = opts.random ?? Math.random;
  let domain: string;
  try {
    domain = normalizeName(rawDomain);
  } catch (err) {
    return { kind: "fail", domain: rawDomain, code: "5.1.2", reason: (err as Error).message };
  }

  let mx: Awaited<ReturnType<Resolver["query"]>>;
  try {
    mx = await opts.resolver.query(domain, "MX");
  } catch (err) {
    if (err instanceof DnsError) {
      return { kind: "defer", domain, code: "dns-temporary", reason: `MX lookup: ${err.message}` };
    }
    throw err;
  }

  if (mx.rcode === Rcode.NXDOMAIN) {
    return { kind: "defer", domain, code: "nxdomain", reason: `${domain} does not exist` };
  }
  if (mx.rcode !== Rcode.NOERROR) {
    return {
      kind: "defer",
      domain,
      code: "dns-temporary",
      reason: `MX lookup for ${domain} failed (rcode ${mx.rcode})`,
    };
  }

  const canonical = mx.records.find((r) => r.type === "MX")?.name ?? domain;
  let hosts: MxHost[] = [];
  let implicit = false;
  for (const r of mx.records) {
    if (r.type === "MX") hosts.push({ host: r.mx.exchange, preference: r.mx.preference });
  }
  if (hosts.length > 0 && hosts.every((h) => h.host === "")) {
    return { kind: "fail", domain, code: "5.1.10", reason: `${domain} accepts no email (null MX)` };
  }
  hosts = hosts.filter((h) => h.host !== "");
  if (hosts.length === 0) {
    implicit = true;
    hosts = [{ host: domain, preference: 0 }];
  }
  hosts = shuffleEqual(hosts, random);

  const targets: Target[] = [];
  const skipped: Skipped[] = [];
  let temporary = false;
  let anyAddress = false;

  for (const h of hosts) {
    if (targets.length >= maxAddresses) break;
    const perFamily: Target[][] = [];
    for (const family of families) {
      try {
        const ans = await opts.resolver.query(h.host, family === 4 ? "A" : "AAAA");
        if (ans.rcode === Rcode.SERVFAIL || ans.rcode === Rcode.REFUSED) temporary = true;
        const list: Target[] = [];
        for (const r of ans.records) {
          if (r.type !== "A" && r.type !== "AAAA") continue;
          anyAddress = true;
          const ownIp = opts.ownAddresses?.some((o) => sameAddress(o, r.address));
          const reason = ownIp
            ? "our own address"
            : opts.allowPrivate
              ? null
              : forbiddenReason(r.address);
          if (reason) skipped.push({ host: h.host, address: r.address, reason });
          else list.push({ host: h.host, preference: h.preference, address: r.address, family });
        }
        perFamily.push(list);
      } catch (err) {
        if (err instanceof DnsError) temporary = true;
        else if (err instanceof DnsWireError) {
          skipped.push({ host: h.host, address: "", reason: "invalid host name" });
          break;
        } else throw err;
      }
    }
    const merged =
      perFamily.length === 2
        ? interleave(perFamily[0] ?? [], perFamily[1] ?? [])
        : (perFamily[0] ?? []);
    for (const t of merged) {
      if (targets.length >= maxAddresses) break;
      targets.push(t);
    }
  }

  if (targets.length > 0) {
    return {
      kind: "targets",
      domain,
      mxHosts: hosts.map((h) => h.host),
      implicit,
      authenticated: mx.authenticated,
      ...(canonical !== domain ? { canonical } : {}),
      targets,
      skipped,
    };
  }
  if (temporary) {
    return {
      kind: "defer",
      domain,
      code: "dns-temporary",
      reason: `could not resolve mail hosts of ${domain}`,
    };
  }
  if (anyAddress) {
    const why = [...new Set(skipped.map((s) => s.reason))].join(", ");
    return {
      kind: "fail",
      domain,
      code: "5.4.4",
      reason: `mail hosts of ${domain} point to a forbidden network (${why})`,
    };
  }
  return { kind: "fail", domain, code: "5.4.4", reason: `mail hosts of ${domain} have no address` };
}
