import {
  type DnsMessage,
  type DsData,
  nameToWire,
  Rcode,
  type ResourceRecord,
  RRType,
} from "../../src/dns/wire.ts";
import { canonicalCompare, nsec3Hash } from "../../src/dnssec/denial.ts";
import { isSubdomain } from "../../src/dnssec/rrset.ts";
import { ds, record, type SignOptions, sign, type ZoneKey, zoneKey } from "./dnssec.ts";

export interface ZoneOptions {
  algorithm?: number;
  signed?: boolean;
  delegated?: boolean;
  sign?: SignOptions;
  denial?: "nsec" | "nsec3";
  optOut?: boolean;
  iterations?: number;
  salt?: Uint8Array;
}

export interface WorldZone extends Required<Omit<ZoneOptions, "algorithm" | "delegated">> {
  name: string;
  ksk: ZoneKey;
  zsk: ZoneKey;
  records: ResourceRecord[];
  proofs: ResourceRecord[];
}

const soa = (zone: string) =>
  record(
    zone,
    RRType.SOA,
    Uint8Array.from([0, 0, 1, 2, 3, 4, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 0, 60, 0, 0, 0, 60]),
    60,
  );

const BASE32HEX = "0123456789abcdefghijklmnopqrstuv";

function base32hex(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32HEX[(value >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32HEX[(value << (5 - bits)) & 31];
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  }
  return a.length - b.length;
}

function bitmap(types: number[]): number[] {
  const out: number[] = [];
  const windows = new Map<number, number[]>();
  for (const t of [...new Set(types)].sort((x, y) => x - y)) {
    const w = t >> 8;
    const bits = windows.get(w) ?? [];
    const i = (t & 0xff) >> 3;
    while (bits.length <= i) bits.push(0);
    bits[i] = (bits[i] as number) | (0x80 >> (t & 7));
    windows.set(w, bits);
  }
  for (const [w, bits] of windows) out.push(w, bits.length, ...bits);
  return out;
}

export class TestWorld {
  readonly zones = new Map<string, WorldZone>();
  readonly queries: { name: string; type: number }[] = [];
  readonly overrides = new Map<string, (m: DnsMessage) => DnsMessage>();
  #answers = new Map<string, ResourceRecord[]>();

  get anchors(): DsData[] {
    const root = this.zones.get("");
    return root ? [ds(root.ksk).ds] : [];
  }

  async zone(name: string, o: ZoneOptions = {}): Promise<WorldZone> {
    const algorithm = o.algorithm ?? 13;
    const z: WorldZone = {
      name,
      ksk: await zoneKey(name, algorithm),
      zsk: await zoneKey(name, algorithm, { ksk: false }),
      records: [soa(name)],
      proofs: [],
      signed: o.signed ?? true,
      sign: o.sign ?? {},
      denial: o.denial ?? "nsec",
      optOut: o.optOut ?? false,
      iterations: o.iterations ?? 0,
      salt: o.salt ?? new Uint8Array(),
    };
    if (name !== "") {
      const parent = this.zoneOf(name, true);
      if (parent) {
        parent.records.push(record(name, RRType.NS, nameToWire(`ns.${name}`)));
        if (z.signed && o.delegated !== false) parent.records.push(ds(z.ksk));
      }
    }
    this.zones.set(name, z);
    return z;
  }

  add(...records: ResourceRecord[]): void {
    for (const r of records) (this.zoneOf(r.name, false) as WorldZone).records.push(r);
  }

  zoneOf(name: string, parentOnly: boolean): WorldZone | undefined {
    let best: WorldZone | undefined;
    for (const z of this.zones.values()) {
      if (parentOnly && z.name === name) continue;
      if (isSubdomain(name, z.name) && (!best || z.name.length > best.name.length)) best = z;
    }
    return best;
  }

  #delegation(z: WorldZone, name: string): boolean {
    return name !== z.name && z.records.some((r) => r.name === name && r.rrtype === RRType.NS);
  }

  #names(z: WorldZone): Map<string, Set<number>> {
    const names = new Map<string, Set<number>>();
    const all = z.signed ? [...z.records, z.ksk.record, z.zsk.record] : z.records;
    for (const r of all) {
      let n = r.name;
      if (!names.has(n)) names.set(n, new Set());
      names.get(n)?.add(r.rrtype);
      while (n !== z.name) {
        n = n.split(".").slice(1).join(".");
        if (!names.has(n)) names.set(n, new Set());
      }
    }
    return names;
  }

  async build(): Promise<void> {
    this.#answers.clear();
    for (const z of this.zones.values()) {
      const groups = new Map<string, ResourceRecord[]>();
      const all = z.signed ? [...z.records, z.ksk.record, z.zsk.record] : z.records;
      for (const r of all) {
        const key = `${r.name}|${r.rrtype}`;
        groups.set(key, [...(groups.get(key) ?? []), r]);
      }
      for (const [key, set] of groups) {
        const first = set[0] as ResourceRecord;
        const out = [...set];
        const delegationNs = first.rrtype === RRType.NS && this.#delegation(z, first.name);
        if (z.signed && !delegationNs) {
          out.push(await sign(set, first.rrtype === RRType.DNSKEY ? z.ksk : z.zsk, z.sign));
        }
        this.#answers.set(`${z.name}#${key}`, out);
      }
      z.proofs = z.signed ? await this.#proofs(z) : [];
    }
  }

  async #proofs(z: WorldZone): Promise<ResourceRecord[]> {
    const names = this.#names(z);
    const typesAt = (n: string) => {
      const t = [...(names.get(n) ?? [])];
      const signedHere = t.some((x) => !(x === RRType.NS && this.#delegation(z, n)));
      return signedHere ? [...t, RRType.RRSIG] : t;
    };
    const out: ResourceRecord[] = [];
    if (z.denial === "nsec") {
      const owners = [...names.keys()].sort(canonicalCompare);
      for (const [i, owner] of owners.entries()) {
        const next = owners[(i + 1) % owners.length] as string;
        const types = [...typesAt(owner), RRType.NSEC, RRType.RRSIG];
        const r = record(
          owner,
          RRType.NSEC,
          Uint8Array.from([...nameToWire(next), ...bitmap(types)]),
          60,
        );
        out.push(r, await sign([r], z.zsk, z.sign));
      }
      return out;
    }
    const unsignedCut = (n: string) =>
      this.#delegation(z, n) && !(names.get(n)?.has(RRType.DS) ?? false);
    const hashed = [...names.keys()]
      .filter((n) => !(z.optOut && unsignedCut(n)))
      .map((n) => ({ n, h: nsec3Hash(n, z.salt, z.iterations) }))
      .sort((x, y) => compareBytes(x.h, y.h));
    for (const [i, { n, h }] of hashed.entries()) {
      const next = (hashed[(i + 1) % hashed.length] as { h: Uint8Array }).h;
      const owner = z.name === "" ? base32hex(h) : `${base32hex(h)}.${z.name}`;
      const head = [
        1,
        z.optOut ? 1 : 0,
        z.iterations >> 8,
        z.iterations & 0xff,
        z.salt.length,
        ...z.salt,
      ];
      const r = record(
        owner,
        RRType.NSEC3,
        Uint8Array.from([...head, next.length, ...next, ...bitmap(typesAt(n))]),
        60,
      );
      out.push(r, await sign([r], z.zsk, z.sign));
    }
    return out;
  }

  #lookup(zone: WorldZone, name: string, type: number): ResourceRecord[] {
    return this.#answers.get(`${zone.name}#${name}|${type}`) ?? [];
  }

  #dname(
    zone: WorldZone,
    name: string,
  ): { records: ResourceRecord[]; alias: ResourceRecord & { type: "CNAME" } } | null {
    const labels = name.split(".");
    for (let i = 1; i <= labels.length; i++) {
      const owner = labels.slice(i).join(".");
      if (!isSubdomain(owner, zone.name)) break;
      const records = this.#lookup(zone, owner, RRType.DNAME);
      const d = records.find((r) => r.type === "DNAME");
      if (d?.type !== "DNAME") continue;
      const prefix = labels.slice(0, i).join(".");
      const target = d.target === "" ? prefix : `${prefix}.${d.target}`;
      const alias = record(name, RRType.CNAME, nameToWire(target), d.ttl);
      return { records, alias: alias as ResourceRecord & { type: "CNAME" } };
    }
    return null;
  }

  fetch = async (name: string, type: number): Promise<DnsMessage> => {
    this.queries.push({ name, type });
    const answers: ResourceRecord[] = [];
    const authority: ResourceRecord[] = [];
    let current = name;
    let rcode: number = Rcode.NOERROR;
    for (let hops = 0; hops < 8; hops++) {
      const zone = this.zoneOf(current, type === RRType.DS) as WorldZone;
      const direct = this.#lookup(zone, current, type);
      if (direct.length > 0) {
        answers.push(...direct);
        break;
      }
      const cname = this.#lookup(zone, current, RRType.CNAME);
      const target = cname.find((r) => r.type === "CNAME");
      if (target?.type === "CNAME") {
        answers.push(...cname);
        current = target.target;
        continue;
      }
      const dname = this.#dname(zone, current);
      if (dname) {
        answers.push(...dname.records, dname.alias);
        current = dname.alias.target;
        continue;
      }
      const names = this.#names(zone);
      if (!names.has(current)) {
        let ce = current;
        while (ce !== zone.name && !names.has(ce)) ce = ce.split(".").slice(1).join(".");
        const star = ce === "" ? "*" : `*.${ce}`;
        const wild = this.#lookup(zone, star, type);
        if (wild.length > 0) {
          answers.push(...wild.map((r) => ({ ...r, name: current })));
          authority.push(...zone.proofs);
          break;
        }
        if (!names.has(star)) rcode = Rcode.NXDOMAIN;
      }
      authority.push(...this.#lookup(zone, zone.name, RRType.SOA), ...zone.proofs);
      break;
    }
    const msg: DnsMessage = {
      id: 0,
      rcode,
      truncated: false,
      authenticated: false,
      question: { name, type },
      answers,
      authority,
    };
    const override = this.overrides.get(`${name}|${type}`);
    return override ? override(msg) : msg;
  };
}

export async function world(
  zones: [string, ZoneOptions?][],
  records: ResourceRecord[] = [],
): Promise<TestWorld> {
  const w = new TestWorld();
  for (const [name, o] of zones) await w.zone(name, o);
  w.add(...records);
  await w.build();
  return w;
}
