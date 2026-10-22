import type { ZoneWire } from "../ns/zone.ts";
import {
  bounceDomain,
  type DomainMode,
  type DomainRecord,
  dkimValue,
  dmarcRecord,
  expectedRecords,
  type PublicDkimKey,
  spfMechanism,
} from "./domains.ts";

export const DKIM_SLOTS = ["bza-r", "bzb-r", "bza-e", "bzb-e"] as const;
export type DkimSlot = (typeof DKIM_SLOTS)[number];
export const SLOT_BASES = ["bza-", "bzb-"] as const;
export const FIRST_SLOTS = SLOT_BASES[0];

const isSlot = (selector: string): selector is DkimSlot =>
  (DKIM_SLOTS as readonly string[]).includes(selector);

export function slotKeys(keys: PublicDkimKey[]): DelegatedDomain["keys"] | null {
  const out: DelegatedDomain["keys"] = {};
  for (const k of keys) {
    if (!isSlot(k.selector)) return null;
    out[k.selector] = k;
  }
  return out;
}

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

export function zoneLabel(domain: string): string {
  const h = new Bun.CryptoHasher("sha256").update(domain.toLowerCase()).digest();
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of h) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5 && out.length < 16) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    if (out.length === 16) break;
    value &= (1 << bits) - 1;
  }
  return out;
}

export function labelClash(name: string, names: string[]): string | null {
  const label = zoneLabel(name);
  return names.find((n) => n !== name && zoneLabel(n) === label) ?? null;
}

export interface DelegatedDomain {
  name: string;
  keys: Partial<Record<DkimSlot, PublicDkimKey>>;
}

export interface ZoneInput {
  zone: string;
  ttl: number;
  sourceIps: string[];
  inboundHost: string | null;
  domains: DelegatedDomain[];
}

export function zoneRecords(input: ZoneInput): ZoneWire["records"] {
  const { zone, ttl } = input;
  const spf = input.sourceIps.length ? `v=spf1 ${spfMechanism(input.sourceIps)} ~all` : null;
  const records: ZoneWire["records"] = [];
  if (spf) records.push({ name: `_spf.${zone}`, type: "TXT", ttl, value: spf });
  for (const d of [...input.domains].sort((a, b) => a.name.localeCompare(b.name))) {
    const owner = `${zoneLabel(d.name)}.${zone}`;
    if (input.inboundHost) {
      records.push({ name: owner, type: "MX", ttl, value: input.inboundHost, priority: 10 });
    }
    if (spf) records.push({ name: owner, type: "TXT", ttl, value: spf });
    for (const slot of DKIM_SLOTS) {
      const key = d.keys[slot];
      if (key) records.push({ name: `${slot}.${owner}`, type: "TXT", ttl, value: dkimValue(key) });
    }
  }
  return records;
}

export function zoneWithSerial(
  zone: string,
  ttl: number,
  records: ZoneWire["records"],
  serial: number,
): ZoneWire {
  return {
    serial,
    records: [...records, { name: `_check.${zone}`, type: "TXT", ttl, value: String(serial) }],
  };
}

export function delegatedRecords(
  domain: string,
  zone: string,
  inboundHost: string | null,
): DomainRecord[] {
  const owner = `${zoneLabel(domain)}.${zone}`;
  const base = { type: "CNAME" as const, status: "not_started" as const, found: null };
  return [
    ...DKIM_SLOTS.map((slot) => ({
      ...base,
      record: "DKIM" as const,
      name: `${slot}._domainkey.${domain}`,
      value: `${slot}.${owner}`,
      required: true,
    })),
    {
      ...base,
      record: "SPF",
      type: "TXT",
      name: domain,
      value: `v=spf1 include:_spf.${zone} ~all`,
      required: false,
    },
    dmarcRecord(domain, inboundHost),
    ...(inboundHost
      ? [
          {
            ...base,
            record: "RETURN_PATH" as const,
            name: bounceDomain(domain),
            value: owner,
            required: false,
          },
        ]
      : []),
  ];
}

export function domainRecords(
  domain: { name: string; mode: DomainMode },
  keys: PublicDkimKey[],
  sourceIp: string | string[] | null,
  inboundHost: string | null,
  zone: string | null,
): DomainRecord[] {
  return domain.mode === "delegated" && zone
    ? delegatedRecords(domain.name, zone, inboundHost)
    : expectedRecords(domain.name, keys, sourceIp, inboundHost);
}
