import { type Nsec3Data, type NsecData, nameToWire, RRType } from "../dns/wire.ts";
import { isSubdomain } from "./rrset.ts";

export type Denial = "nxdomain" | "nodata" | "insecure";

export interface NsecRecord {
  owner: string;
  nsec: NsecData;
}

export interface Nsec3Record {
  owner: string;
  nsec3: Nsec3Data;
}

export const MAX_NSEC3_ITERATIONS = 50;
const OPT_OUT = 1;

const labels = (name: string) => (name === "" ? [] : name.split("."));

export function canonicalCompare(a: string, b: string): number {
  const x = labels(a).reverse();
  const y = labels(b).reverse();
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const p = x[i] as string;
    const q = y[i] as string;
    if (p === q) continue;
    const n = Math.min(p.length, q.length);
    for (let j = 0; j < n; j++) {
      const d = p.charCodeAt(j) - q.charCodeAt(j);
      if (d !== 0) return d;
    }
    return p.length - q.length;
  }
  return x.length - y.length;
}

function between(owner: string, next: string, name: string): boolean {
  if (canonicalCompare(owner, next) < 0) {
    return canonicalCompare(owner, name) < 0 && canonicalCompare(name, next) < 0;
  }
  return canonicalCompare(owner, name) < 0 || canonicalCompare(name, next) < 0;
}

const has = (types: number[], t: number) => types.includes(t);

function parentSide(types: number[]): boolean {
  return has(types, RRType.NS) && !has(types, RRType.SOA);
}

function usableNsec(r: NsecRecord, name: string): boolean {
  if (r.owner === name) return true;
  if (!isSubdomain(name, r.owner)) return true;
  return !parentSide(r.nsec.types) && !has(r.nsec.types, RRType.DNAME);
}

function coveringNsec(list: NsecRecord[], name: string): NsecRecord | undefined {
  return list.find((r) => usableNsec(r, name) && between(r.owner, r.nsec.next, name));
}

function closestEncloser(name: string, r: NsecRecord): string {
  const parts = labels(name);
  for (let i = 1; i <= parts.length; i++) {
    const ce = parts.slice(i).join(".");
    if (isSubdomain(r.owner, ce) || isSubdomain(r.nsec.next, ce)) return ce;
  }
  return "";
}

const wildcard = (ce: string) => (ce === "" ? "*" : `*.${ce}`);

export function nsecDenial(list: NsecRecord[], name: string, type: number): Denial | null {
  const exact = list.find((r) => r.owner === name);
  if (exact) {
    const t = exact.nsec.types;
    if (has(t, type) || has(t, RRType.CNAME)) return null;
    if (type === RRType.DS) {
      if (has(t, RRType.SOA)) return null;
      return has(t, RRType.NS) ? "insecure" : "nodata";
    }
    return parentSide(t) ? null : "nodata";
  }
  const cover = coveringNsec(list, name);
  if (!cover) return null;
  if (isSubdomain(cover.nsec.next, name) && cover.nsec.next !== name) return "nodata";
  const ce = closestEncloser(name, cover);
  const star = wildcard(ce);
  const wild = list.find((r) => r.owner === star);
  if (wild) {
    if (has(wild.nsec.types, type) || has(wild.nsec.types, RRType.CNAME)) return null;
    return "nodata";
  }
  return coveringNsec(list, star) ? "nxdomain" : null;
}

export function nsecWildcardProof(list: NsecRecord[], name: string): boolean {
  return coveringNsec(list, name) !== undefined;
}

const BASE32HEX = "0123456789abcdefghijklmnopqrstuv";

function base32hexDecode(text: string): Uint8Array | null {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of text.toLowerCase()) {
    const v = BASE32HEX.indexOf(ch);
    if (v < 0) return null;
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

export function nsec3Hash(name: string, salt: Uint8Array, iterations: number): Uint8Array {
  let x: Uint8Array = nameToWire(name);
  for (let i = 0; i <= iterations; i++) {
    const h = new Bun.CryptoHasher("sha1");
    h.update(x);
    h.update(salt);
    x = new Uint8Array(h.digest());
  }
  return x;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  }
  return a.length - b.length;
}

interface Hashed {
  record: Nsec3Record;
  owner: Uint8Array;
}

export type Nsec3Verdict = Denial | "too-many-iterations" | null;

export function nsec3Denial(
  list: Nsec3Record[],
  zone: string,
  name: string,
  type: number,
): Nsec3Verdict {
  const usable: Hashed[] = [];
  for (const r of list) {
    const n = r.nsec3;
    if (n.hashAlgorithm !== 1 || (n.flags & ~OPT_OUT) !== 0) continue;
    if (!r.owner.endsWith(zone === "" ? "" : `.${zone}`) && zone !== "") continue;
    const first = r.owner.split(".")[0] ?? "";
    const owner = base32hexDecode(first);
    if (!owner || owner.length !== n.nextHashed.length) continue;
    usable.push({ record: r, owner });
  }
  if (usable.length === 0) return null;
  if (usable.some((h) => h.record.nsec3.iterations > MAX_NSEC3_ITERATIONS))
    return "too-many-iterations";

  const hashOf = (n: string, h: Hashed) =>
    nsec3Hash(n, h.record.nsec3.salt, h.record.nsec3.iterations);
  const matching = (n: string) => usable.find((h) => compareBytes(h.owner, hashOf(n, h)) === 0);
  const covering = (n: string) =>
    usable.find((h) => {
      const x = hashOf(n, h);
      const next = h.record.nsec3.nextHashed;
      if (compareBytes(h.owner, next) < 0)
        return compareBytes(h.owner, x) < 0 && compareBytes(x, next) < 0;
      return compareBytes(h.owner, x) < 0 || compareBytes(x, next) < 0;
    });

  const exact = matching(name);
  if (exact) {
    const t = exact.record.nsec3.types;
    if (has(t, type) || has(t, RRType.CNAME)) return null;
    if (type === RRType.DS) {
      if (has(t, RRType.SOA)) return null;
      return has(t, RRType.NS) ? "insecure" : "nodata";
    }
    return parentSide(t) ? null : "nodata";
  }

  const parts = labels(name);
  const zoneLabels = labels(zone).length;
  for (let i = 1; parts.length - i >= zoneLabels; i++) {
    const ce = parts.slice(i).join(".");
    const enc = matching(ce);
    if (!enc) continue;
    const t = enc.record.nsec3.types;
    if (has(t, RRType.DNAME) || (has(t, RRType.NS) && !has(t, RRType.SOA))) return null;
    const nextCloser = parts.slice(i - 1).join(".");
    const cover = covering(nextCloser);
    if (!cover) return null;
    if (type === RRType.DS && (cover.record.nsec3.flags & OPT_OUT) !== 0) return "insecure";
    const wild = matching(wildcard(ce));
    if (wild) {
      if (has(wild.record.nsec3.types, type) || has(wild.record.nsec3.types, RRType.CNAME))
        return null;
      return "nodata";
    }
    if (!covering(wildcard(ce))) return null;
    return (cover.record.nsec3.flags & OPT_OUT) !== 0 ? "insecure" : "nxdomain";
  }
  return null;
}

export function nsec3WildcardProof(
  list: Nsec3Record[],
  zone: string,
  name: string,
  wildcardLabels: number,
): boolean {
  const parts = labels(name);
  const nextCloser = parts.slice(parts.length - wildcardLabels - 1).join(".");
  for (const r of list) {
    const n = r.nsec3;
    if (n.hashAlgorithm !== 1 || (n.flags & ~OPT_OUT) !== 0 || n.iterations > MAX_NSEC3_ITERATIONS)
      continue;
    if (zone !== "" && !r.owner.endsWith(`.${zone}`)) continue;
    const owner = base32hexDecode(r.owner.split(".")[0] ?? "");
    if (!owner) continue;
    const x = nsec3Hash(nextCloser, n.salt, n.iterations);
    const inside =
      compareBytes(owner, n.nextHashed) < 0
        ? compareBytes(owner, x) < 0 && compareBytes(x, n.nextHashed) < 0
        : compareBytes(owner, x) < 0 || compareBytes(x, n.nextHashed) < 0;
    if (inside) return true;
  }
  return false;
}
