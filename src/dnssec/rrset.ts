import { type DnskeyData, nameToWire, type ResourceRecord, type RrsigData } from "../dns/wire.ts";
import { verifySignature } from "./crypto.ts";

const ZONE_KEY = 0x0100;

export type SigCheck = { ok: true } | { ok: false; reason: string };

export function labelCount(name: string): number {
  return name === "" ? 0 : name.split(".").length;
}

export function isSubdomain(name: string, zone: string): boolean {
  return zone === "" || name === zone || name.endsWith(`.${zone}`);
}

function serialBefore(a: number, b: number): boolean {
  return ((a - b) | 0) < 0;
}

function compare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  }
  return a.length - b.length;
}

export function signedData(rrset: ResourceRecord[], sig: RrsigData): Uint8Array {
  const owner = rrset[0]?.name ?? "";
  const labels = owner === "" ? [] : owner.split(".");
  const name =
    sig.labels < labels.length
      ? ["*", ...labels.slice(labels.length - sig.labels)].join(".")
      : owner;
  const ownerWire = nameToWire(name);
  const rdatas = rrset
    .map((r) => r.rdata)
    .sort(compare)
    .filter((r, i, all) => i === 0 || compare(r, all[i - 1] as Uint8Array) !== 0);

  const head = new Uint8Array(18);
  const hv = new DataView(head.buffer);
  hv.setUint16(0, sig.typeCovered);
  hv.setUint8(2, sig.algorithm);
  hv.setUint8(3, sig.labels);
  hv.setUint32(4, sig.originalTtl);
  hv.setUint32(8, sig.expiration);
  hv.setUint32(12, sig.inception);
  hv.setUint16(16, sig.keyTag);
  const signer = nameToWire(sig.signer);

  const size =
    head.length + signer.length + rdatas.reduce((n, r) => n + ownerWire.length + 10 + r.length, 0);
  const out = new Uint8Array(size);
  const v = new DataView(out.buffer);
  out.set(head, 0);
  out.set(signer, head.length);
  let at = head.length + signer.length;
  for (const r of rdatas) {
    out.set(ownerWire, at);
    at += ownerWire.length;
    v.setUint16(at, sig.typeCovered);
    v.setUint16(at + 2, 1);
    v.setUint32(at + 4, sig.originalTtl);
    v.setUint16(at + 8, r.length);
    out.set(r, at + 10);
    at += 10 + r.length;
  }
  return out;
}

export function checkSignatureFields(
  rrset: ResourceRecord[],
  sig: RrsigData,
  zone: string,
  now: number,
): string | null {
  const first = rrset[0];
  if (!first) return "empty RRset";
  if (rrset.some((r) => r.name !== first.name || r.rrtype !== first.rrtype))
    return "the RRset mixes names or types";
  if (sig.typeCovered !== first.rrtype) return "the signature covers another type";
  if (sig.signer !== zone) return `signed by ${sig.signer || "."}, not by ${zone || "."}`;
  if (!isSubdomain(first.name, zone)) return `${first.name} is outside ${zone || "."}`;
  if (sig.labels > labelCount(first.name)) return "the signature has too many labels";
  const t = Math.floor(now / 1000) >>> 0;
  if (serialBefore(sig.expiration, t)) return "the signature has expired";
  if (serialBefore(t, sig.inception)) return "the signature is not valid yet";
  return null;
}

export async function verifyRrset(
  rrset: ResourceRecord[],
  sig: RrsigData,
  zone: string,
  keys: DnskeyData[],
  now: number,
): Promise<SigCheck> {
  const problem = checkSignatureFields(rrset, sig, zone, now);
  if (problem) return { ok: false, reason: problem };
  const candidates = keys.filter(
    (k) =>
      k.keyTag === sig.keyTag &&
      k.algorithm === sig.algorithm &&
      k.protocol === 3 &&
      (k.flags & ZONE_KEY) !== 0,
  );
  if (candidates.length === 0)
    return { ok: false, reason: `no key ${sig.keyTag} in ${zone || "."}` };
  const data = signedData(rrset, sig);
  for (const k of candidates) {
    if (await verifySignature(k, sig.signature, data)) return { ok: true };
  }
  return { ok: false, reason: `the signature by key ${sig.keyTag} does not verify` };
}
