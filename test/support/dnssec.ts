import { decodeMessage, nameToWire, type ResourceRecord } from "../../src/dns/wire.ts";
import { signedData } from "../../src/dnssec/rrset.ts";

export interface ZoneKey {
  zone: string;
  algorithm: number;
  flags: number;
  record: ResourceRecord & { type: "DNSKEY" };
  privateKey: CryptoKey;
}

const DAY = 86_400;

export function record(name: string, type: number, rdata: Uint8Array, ttl = 3600): ResourceRecord {
  const owner = nameToWire(name);
  const msg = new Uint8Array(12 + owner.length + 10 + rdata.length);
  const v = new DataView(msg.buffer);
  v.setUint16(2, 0x8180);
  v.setUint16(6, 1);
  msg.set(owner, 12);
  const at = 12 + owner.length;
  v.setUint16(at, type);
  v.setUint16(at + 2, 1);
  v.setUint32(at + 4, ttl);
  v.setUint16(at + 8, rdata.length);
  msg.set(rdata, at + 10);
  return decodeMessage(msg).answers[0] as ResourceRecord;
}

export const a = (name: string, ip: string) =>
  record(name, 1, Uint8Array.from(ip.split(".").map(Number)));

function generation(algorithm: number, bits: number) {
  const rsa = (hash: string) => ({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: bits,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash,
  });
  switch (algorithm) {
    case 8:
      return rsa("SHA-256");
    case 10:
      return rsa("SHA-512");
    case 13:
      return { name: "ECDSA", namedCurve: "P-256" };
    case 14:
      return { name: "ECDSA", namedCurve: "P-384" };
    default:
      return { name: "Ed25519" };
  }
}

export async function zoneKey(
  zone: string,
  algorithm = 13,
  { ksk = true, bits = 2048 }: { ksk?: boolean; bits?: number } = {},
): Promise<ZoneKey> {
  const keys = (await crypto.subtle.generateKey(
    generation(algorithm, bits) as { name: "ECDSA"; namedCurve: string },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  let publicKey: Uint8Array;
  if (algorithm === 8 || algorithm === 10) {
    const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    const e = Uint8Array.fromBase64(jwk.e as string, { alphabet: "base64url" });
    const n = Uint8Array.fromBase64(jwk.n as string, { alphabet: "base64url" });
    publicKey = Uint8Array.from([e.length, ...e, ...n]);
  } else {
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    publicKey = algorithm === 15 ? raw : raw.subarray(1);
  }
  const flags = ksk ? 257 : 256;
  const rdata = Uint8Array.from([flags >> 8, flags & 0xff, 3, algorithm, ...publicKey]);
  const rec = record(zone, 48, rdata) as ResourceRecord & { type: "DNSKEY" };
  return { zone, algorithm, flags, record: rec, privateKey: keys.privateKey };
}

export interface SignOptions {
  now?: number;
  inception?: number;
  expiration?: number;
  labels?: number;
  keyTag?: number;
}

export async function sign(
  rrset: ResourceRecord[],
  key: ZoneKey,
  o: SignOptions = {},
): Promise<ResourceRecord & { type: "RRSIG" }> {
  const first = rrset[0] as ResourceRecord;
  const now = Math.floor((o.now ?? Date.now()) / 1000);
  const fields = {
    typeCovered: first.rrtype,
    algorithm: key.algorithm,
    labels:
      o.labels ??
      first.name.split(".").filter((l, i) => l !== "" && !(i === 0 && l === "*")).length,
    originalTtl: first.ttl,
    expiration: (o.expiration ?? now + 7 * DAY) >>> 0,
    inception: (o.inception ?? now - DAY) >>> 0,
    keyTag: o.keyTag ?? key.record.dnskey.keyTag,
    signer: key.zone,
    signature: new Uint8Array(),
  };
  const data = signedData(rrset, fields) as Uint8Array<ArrayBuffer>;
  let signature: Uint8Array;
  if (key.algorithm === 8 || key.algorithm === 10) {
    signature = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, data));
  } else if (key.algorithm === 15) {
    signature = new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, data));
  } else {
    const hash = key.algorithm === 13 ? "SHA-256" : "SHA-384";
    signature = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash }, key.privateKey, data),
    );
  }
  const head = new Uint8Array(18);
  const v = new DataView(head.buffer);
  v.setUint16(0, fields.typeCovered);
  v.setUint8(2, fields.algorithm);
  v.setUint8(3, fields.labels);
  v.setUint32(4, fields.originalTtl);
  v.setUint32(8, fields.expiration);
  v.setUint32(12, fields.inception);
  v.setUint16(16, fields.keyTag);
  const rdata = Uint8Array.from([...head, ...nameToWire(key.zone), ...signature]);
  return record(first.name, 46, rdata, first.ttl) as ResourceRecord & { type: "RRSIG" };
}

export function ds(key: ZoneKey, digestType = 2): ResourceRecord & { type: "DS" } {
  const h = new Bun.CryptoHasher(digestType === 4 ? "sha384" : "sha256");
  h.update(nameToWire(key.zone));
  h.update(key.record.rdata);
  const digest = new Uint8Array(h.digest());
  const tag = key.record.dnskey.keyTag;
  const rdata = Uint8Array.from([tag >> 8, tag & 0xff, key.algorithm, digestType, ...digest]);
  return record(key.zone, 43, rdata) as ResourceRecord & { type: "DS" };
}
