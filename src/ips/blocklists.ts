import { parseIPv4, parseIPv6 } from "../dns/ip.ts";
import type { Resolver } from "../dns/resolver.ts";

export interface Blocklist {
  id: string;
  name: string;
  zone: string;
  removal: string;
  ipv6: boolean;
  errors?: string[];
  meaning?: (code: string) => string | null;
}

export type ListingStatus = "clean" | "listed" | "unusable";

export interface Listing {
  list: string;
  name: string;
  status: ListingStatus;
  detail: string;
  removal: string | null;
}

const NXDOMAIN = 3;

function spamhausMeaning(code: string): string | null {
  const last = Number(code.split(".")[3]);
  if (last === 2) return "SBL: a known spam source";
  if (last === 3) return "CSS: a low-reputation sender";
  if (last >= 4 && last <= 7) return "XBL: an infected or exploited host";
  if (last === 9) return "DROP: a hijacked network";
  if (last === 10 || last === 11) {
    return "PBL: the network owner says this IP should not send email directly";
  }
  return null;
}

export function blocklists(spamhausKey: string | null): Blocklist[] {
  return [
    {
      id: "spamhaus",
      name: "Spamhaus ZEN",
      zone: spamhausKey ? `${spamhausKey}.zen.dq.spamhaus.net` : "zen.spamhaus.org",
      removal: "https://check.spamhaus.org/",
      ipv6: true,
      errors: ["127.255.255.252", "127.255.255.254", "127.255.255.255"],
      meaning: spamhausMeaning,
    },
    {
      id: "barracuda",
      name: "Barracuda",
      zone: "b.barracudacentral.org",
      removal: "https://www.barracudacentral.org/rbl/removal-request",
      ipv6: false,
    },
    {
      id: "spamcop",
      name: "SpamCop",
      zone: "bl.spamcop.net",
      removal: "https://www.spamcop.net/bl.shtml",
      ipv6: false,
    },
    {
      id: "mailspike",
      name: "Mailspike",
      zone: "bl.mailspike.net",
      removal: "https://mailspike.io/ip_verify",
      ipv6: false,
    },
    {
      id: "psbl",
      name: "PSBL",
      zone: "psbl.surriel.com",
      removal: "https://psbl.org/remove",
      ipv6: false,
    },
  ];
}

export function listName(ip: string): string | null {
  const v4 = parseIPv4(ip);
  if (v4) return [...v4].reverse().join(".");
  const v6 = parseIPv6(ip);
  if (!v6) return null;
  return [...v6]
    .flatMap((b) => [b >> 4, b & 15])
    .reverse()
    .map((n) => n.toString(16))
    .join(".");
}

type Answer =
  | { kind: "none" }
  | { kind: "codes"; codes: string[] }
  | { kind: "failed"; why: string };

async function lookup(resolver: Resolver, name: string): Promise<Answer> {
  try {
    const a = await resolver.query(name, "A");
    const codes = a.records.flatMap((r) => (r.type === "A" ? [r.address] : []));
    if (codes.length > 0) return { kind: "codes", codes };
    if (a.rcode === NXDOMAIN || a.rcode === 0) return { kind: "none" };
    return { kind: "failed", why: `the lookup failed (rcode ${a.rcode})` };
  } catch (err) {
    return { kind: "failed", why: `the lookup failed: ${(err as Error).message}` };
  }
}

const loopback = (code: string) => code.startsWith("127.");

async function usable(resolver: Resolver, list: Blocklist): Promise<string | null> {
  const listed = await lookup(resolver, `2.0.0.127.${list.zone}`);
  if (listed.kind === "failed") return listed.why;
  if (listed.kind === "codes" && listed.codes.some((c) => list.errors?.includes(c))) {
    return list.id === "spamhaus"
      ? "Spamhaus refuses queries from this resolver: use a local resolver or set BUNZZLE_SPAMHAUS_KEY_FILE"
      : "the list refuses queries from this resolver";
  }
  if (listed.kind !== "codes" || !listed.codes.every(loopback)) {
    return "the resolver does not return the list's test entry 127.0.0.2";
  }
  const clean = await lookup(resolver, `1.0.0.127.${list.zone}`);
  if (clean.kind === "failed") return clean.why;
  if (clean.kind === "codes") return "the resolver answers for names that do not exist";
  return null;
}

export async function checkBlocklists(
  resolver: Resolver,
  ip: string,
  lists: Blocklist[],
): Promise<Listing[]> {
  const name = listName(ip);
  if (!name) return [];
  const v6 = parseIPv4(ip) === null;
  const out: Listing[] = [];
  for (const list of lists) {
    if (v6 && !list.ipv6) continue;
    const base = { list: list.id, name: list.name };
    const problem = await usable(resolver, list);
    if (problem) {
      out.push({ ...base, status: "unusable", detail: problem, removal: null });
      continue;
    }
    const a = await lookup(resolver, `${name}.${list.zone}`);
    if (a.kind === "none") {
      out.push({ ...base, status: "clean", detail: "not listed", removal: null });
    } else if (a.kind === "failed") {
      out.push({ ...base, status: "unusable", detail: a.why, removal: null });
    } else if (a.codes.some((c) => list.errors?.includes(c) || !loopback(c))) {
      out.push({
        ...base,
        status: "unusable",
        detail: `unexpected answer ${a.codes.join(", ")}`,
        removal: null,
      });
    } else {
      const meanings = list.meaning ? a.codes.map((c) => list.meaning?.(c) ?? `listed (${c})`) : [];
      out.push({
        ...base,
        status: "listed",
        detail: meanings.length
          ? [...new Set(meanings)].join("; ")
          : `listed (${a.codes.join(", ")})`,
        removal: list.removal,
      });
    }
  }
  return out;
}
