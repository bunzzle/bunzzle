import { parseIPv4, parseIPv6 } from "../dns/ip.ts";
import { type DnsWireError, nameToWire, normalizeName, RRType } from "../dns/wire.ts";
import { b } from "../validate/schema.ts";

export const UDP_LIMIT = 1232;
export const NEGATIVE_TTL = 300;
export const NS_TTL = 3600;
const SOA_REFRESH = 3600;
const SOA_RETRY = 600;
const SOA_EXPIRE = 1_209_600;
const QUESTION_MAX = 255 + 4;
const OPT_SIZE = 11;
const HEADER = 12;

export const zoneWire = b.object({
  serial: b.number().int().min(0).max(0xffffffff),
  records: b
    .array(
      b.object({
        name: b.string().min(1).max(253),
        type: b.enum(["A", "AAAA", "MX", "TXT"]),
        ttl: b.number().int().min(0).max(604_800),
        value: b.string().min(1).max(4096),
        priority: b.number().int().min(0).max(65535).optional(),
      }),
    )
    .max(200_000),
});
export type ZoneWire = b.infer<typeof zoneWire>;

export class ZoneError extends Error {}

export interface RRSet {
  count: number;
  bytes: Uint8Array;
}

export interface Zone {
  apex: string;
  apexWire: Uint8Array;
  serial: number;
  names: Map<string, Map<number, RRSet>>;
  soa: Uint8Array;
  hinfo: Uint8Array;
}

function u16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}

function u32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function body(type: number, ttl: number, rdata: Uint8Array | number[]): number[] {
  return [...u16(type), ...u16(1), ...u32(ttl), ...u16(rdata.length), ...rdata];
}

function rrset(type: number, ttl: number, rdatas: (Uint8Array | number[])[]): RRSet {
  const out: number[] = [];
  for (const rdata of rdatas) out.push(0xc0, 0x0c, ...body(type, ttl, rdata));
  return { count: rdatas.length, bytes: Uint8Array.from(out) };
}

function txtData(value: string): number[] {
  if (!/^[\x20-\x7e]+$/.test(value)) throw new ZoneError("TXT values must be printable ASCII");
  const bytes = new TextEncoder().encode(value);
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i += 255) {
    const part = bytes.subarray(i, i + 255);
    out.push(part.length, ...part);
  }
  return out;
}

function rdataOf(r: ZoneWire["records"][number]): Uint8Array | number[] {
  switch (r.type) {
    case "A": {
      const ip = parseIPv4(r.value);
      if (!ip) throw new ZoneError(`invalid A address: ${r.value}`);
      return ip;
    }
    case "AAAA": {
      const ip = parseIPv6(r.value);
      if (!ip) throw new ZoneError(`invalid AAAA address: ${r.value}`);
      return ip;
    }
    case "MX":
      return [...u16(r.priority ?? 10), ...nameToWire(normalizeName(r.value))];
    case "TXT":
      return txtData(r.value);
  }
}

export function inZone(name: string, apex: string): boolean {
  return name === apex || name.endsWith(`.${apex}`);
}

export function buildZone(apex: string, nsNames: string[], wire: ZoneWire): Zone {
  const names = new Map<string, Map<number, RRSet>>();
  const grouped = new Map<
    string,
    { type: number; ttl: number; rdatas: (Uint8Array | number[])[] }
  >();
  for (const r of wire.records) {
    let name: string;
    try {
      name = normalizeName(r.name);
    } catch (err) {
      throw new ZoneError((err as DnsWireError).message);
    }
    if (!inZone(name, apex)) throw new ZoneError(`${name} is outside the zone ${apex}`);
    const type = RRType[r.type];
    const key = `${name} ${type}`;
    const g = grouped.get(key) ?? { type, ttl: r.ttl, rdatas: [] };
    g.ttl = Math.min(g.ttl, r.ttl);
    g.rdatas.push(rdataOf(r));
    grouped.set(key, g);
    for (let n = name; ; n = n.slice(n.indexOf(".") + 1)) {
      if (!names.has(n)) names.set(n, new Map());
      if (n === apex) break;
    }
  }
  for (const [key, g] of grouped) {
    const name = key.slice(0, key.indexOf(" "));
    const set = rrset(g.type, g.ttl, g.rdatas);
    const size = HEADER + QUESTION_MAX + set.bytes.length + OPT_SIZE;
    if (size > UDP_LIMIT) {
      throw new ZoneError(`${name} answer would be ${size} bytes, more than ${UDP_LIMIT}`);
    }
    names.get(name)?.set(g.type, set);
  }
  const apexSet = names.get(apex) ?? new Map<number, RRSet>();
  names.set(apex, apexSet);
  apexSet.set(
    RRType.NS,
    rrset(
      RRType.NS,
      NS_TTL,
      nsNames.map((n) => nameToWire(n)),
    ),
  );
  const soaData = [
    ...nameToWire(nsNames[0] as string),
    ...nameToWire(`hostmaster.${apex}`),
    ...u32(wire.serial),
    ...u32(SOA_REFRESH),
    ...u32(SOA_RETRY),
    ...u32(SOA_EXPIRE),
    ...u32(NEGATIVE_TTL),
  ];
  apexSet.set(RRType.SOA, rrset(RRType.SOA, NEGATIVE_TTL, [soaData]));
  const reason = new TextEncoder().encode("RFC8482");
  return {
    apex,
    apexWire: nameToWire(apex),
    serial: wire.serial,
    names,
    soa: Uint8Array.from(body(RRType.SOA, NEGATIVE_TTL, soaData)),
    hinfo: rrset(13, NEGATIVE_TTL, [[reason.length, ...reason, 0]]).bytes,
  };
}
