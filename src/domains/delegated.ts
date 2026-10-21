import type { ZoneWire } from "../ns/zone.ts";
import { dkimValue, type PublicDkimKey, spfMechanism } from "./domains.ts";

export const DKIM_SLOTS = ["bza-r", "bzb-r", "bza-e", "bzb-e"] as const;
export type DkimSlot = (typeof DKIM_SLOTS)[number];

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
