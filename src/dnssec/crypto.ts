import { type DnskeyData, type DsData, nameToWire } from "../dns/wire.ts";

export const ALGORITHMS = new Set([8, 10, 13, 14, 15]);
export const DIGESTS = new Set([2, 4]);

const MIN_RSA_BITS = 1024;
const MAX_RSA_BITS = 4096;

const buf = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
const b64u = (b: Uint8Array) => b.toBase64({ alphabet: "base64url", omitPadding: true });

function rsaJwk(key: Uint8Array): { n: string; e: string; bits: number } | null {
  if (key.length < 3) return null;
  let at = 1;
  let eLen = key[0] as number;
  if (eLen === 0) {
    eLen = ((key[1] as number) << 8) | (key[2] as number);
    at = 3;
  }
  if (eLen === 0 || at + eLen >= key.length) return null;
  const e = key.subarray(at, at + eLen);
  let n = key.subarray(at + eLen);
  while (n.length > 0 && n[0] === 0) n = n.subarray(1);
  const bits = n.length * 8 - Math.clz32(n[0] ?? 0) + 24;
  return { n: b64u(n), e: b64u(e), bits };
}

type VerifyAlgorithm = Parameters<typeof crypto.subtle.verify>[0];

async function importKey(
  key: DnskeyData,
): Promise<{ key: CryptoKey; alg: VerifyAlgorithm } | null> {
  switch (key.algorithm) {
    case 8:
    case 10: {
      const jwk = rsaJwk(key.publicKey);
      if (!jwk || jwk.bits < MIN_RSA_BITS || jwk.bits > MAX_RSA_BITS) return null;
      const hash = key.algorithm === 8 ? "SHA-256" : "SHA-512";
      const k = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n: jwk.n, e: jwk.e, ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash },
        false,
        ["verify"],
      );
      return { key: k, alg: "RSASSA-PKCS1-v1_5" };
    }
    case 13:
    case 14: {
      const size = key.algorithm === 13 ? 64 : 96;
      if (key.publicKey.length !== size) return null;
      const point = new Uint8Array(size + 1);
      point[0] = 4;
      point.set(key.publicKey, 1);
      const namedCurve = key.algorithm === 13 ? "P-256" : "P-384";
      const k = await crypto.subtle.importKey("raw", point, { name: "ECDSA", namedCurve }, false, [
        "verify",
      ]);
      return { key: k, alg: { name: "ECDSA", hash: key.algorithm === 13 ? "SHA-256" : "SHA-384" } };
    }
    case 15: {
      if (key.publicKey.length !== 32) return null;
      const k = await crypto.subtle.importKey(
        "raw",
        buf(key.publicKey),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return { key: k, alg: "Ed25519" };
    }
    default:
      return null;
  }
}

export async function verifySignature(
  key: DnskeyData,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  try {
    const imported = await importKey(key);
    if (!imported) return false;
    return await crypto.subtle.verify(imported.alg, imported.key, buf(signature), buf(data));
  } catch {
    return false;
  }
}

export function dsMatches(ds: DsData, owner: string, key: DnskeyData, rdata: Uint8Array): boolean {
  if (ds.keyTag !== key.keyTag || ds.algorithm !== key.algorithm) return false;
  const name = ds.digestType === 2 ? "sha256" : ds.digestType === 4 ? "sha384" : null;
  if (!name) return false;
  const h = new Bun.CryptoHasher(name);
  h.update(nameToWire(owner));
  h.update(rdata);
  const digest = new Uint8Array(h.digest());
  return digest.length === ds.digest.length && digest.every((b, i) => b === ds.digest[i]);
}
