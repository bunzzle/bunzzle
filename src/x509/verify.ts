import { DerError, tlv } from "../asn1/der.ts";
import { type Algorithm, algorithm, type Certificate, KEY_CERT_SIGN, oidString } from "./cert.ts";

const MAX_DEPTH = 8;
const MIN_RSA_BITS = 2048;
const SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
const ANY_PURPOSE = "2.5.29.37.0";

const RSA_KEY = "1.2.840.113549.1.1.1";
const EC_KEY = "1.2.840.10045.2.1";
const ED25519 = "1.3.101.112";
const PSS = "1.2.840.113549.1.1.10";

const HASHES: Record<string, string> = {
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
};
const RSA_PKCS1: Record<string, string> = {
  "1.2.840.113549.1.1.11": "SHA-256",
  "1.2.840.113549.1.1.12": "SHA-384",
  "1.2.840.113549.1.1.13": "SHA-512",
};
const ECDSA: Record<string, string> = {
  "1.2.840.10045.4.3.2": "SHA-256",
  "1.2.840.10045.4.3.3": "SHA-384",
  "1.2.840.10045.4.3.4": "SHA-512",
};
const CURVES: Record<string, { name: string; size: number }> = {
  "1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
  "1.3.132.0.34": { name: "P-384", size: 48 },
  "1.3.132.0.35": { name: "P-521", size: 66 },
};

const buf = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

function keyAlgorithm(spki: Uint8Array): Algorithm {
  const top = tlv(spki, 0);
  return algorithm(spki, tlv(spki, top.body));
}

function ecdsaRaw(sig: Uint8Array, size: number): Uint8Array {
  const top = tlv(sig, 0);
  if (top.tag !== 0x30 || top.end !== sig.length) throw new DerError("bad ECDSA signature");
  const r = tlv(sig, top.body);
  const s = tlv(sig, r.end);
  if (r.tag !== 0x02 || s.tag !== 0x02 || s.end !== top.end)
    throw new DerError("bad ECDSA signature");
  const out = new Uint8Array(size * 2);
  for (const [i, t] of [r, s].entries()) {
    let v = sig.subarray(t.body, t.end);
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > size) throw new DerError("bad ECDSA signature");
    out.set(v, size * (i + 1) - v.length);
  }
  return out;
}

function pssParams(params: Uint8Array | null): { hash: string; saltLength: number } {
  if (!params) throw new DerError("RSA-PSS without parameters (SHA-1)");
  const top = tlv(params, 0);
  let hash: string | null = null;
  let mgfHash: string | null = null;
  let saltLength = 20;
  for (let at = top.body; at < top.end; ) {
    const field = tlv(params, at);
    const inner = tlv(params, field.body);
    if (field.tag === 0xa0) {
      hash = HASHES[algorithm(params, inner).oid] ?? null;
    } else if (field.tag === 0xa1) {
      const mgf = algorithm(params, inner);
      if (mgf.oid !== "1.2.840.113549.1.1.8" || !mgf.params) throw new DerError("unknown PSS mask");
      mgfHash = HASHES[algorithm(mgf.params, tlv(mgf.params, 0)).oid] ?? null;
    } else if (field.tag === 0xa2) {
      saltLength = params.subarray(inner.body, inner.end).reduce((a, b) => a * 256 + b, 0);
    } else if (field.tag === 0xa3) {
      if (params.subarray(inner.body, inner.end).reduce((a, b) => a * 256 + b, 0) !== 1)
        throw new DerError("unknown PSS trailer");
    }
    at = field.end;
  }
  if (!hash || hash !== mgfHash) throw new DerError("unsupported RSA-PSS parameters");
  return { hash, saltLength };
}

async function rsaKey(spki: Uint8Array, alg: { name: string; hash: string }): Promise<CryptoKey> {
  const key = await crypto.subtle.importKey("spki", buf(spki), alg, false, ["verify"]);
  const bits = (key.algorithm as CryptoKey["algorithm"] & { modulusLength?: number }).modulusLength;
  if ((bits ?? 0) < MIN_RSA_BITS) throw new DerError("RSA key shorter than 2048 bits");
  return key;
}

export async function verifySignature(
  cert: Pick<Certificate, "tbs" | "signature" | "signatureAlgorithm">,
  issuerSpki: Uint8Array,
): Promise<boolean> {
  try {
    const sig = cert.signatureAlgorithm;
    const key = keyAlgorithm(issuerSpki);
    if (RSA_PKCS1[sig.oid] && key.oid === RSA_KEY) {
      const name = "RSASSA-PKCS1-v1_5";
      const k = await rsaKey(issuerSpki, { name, hash: RSA_PKCS1[sig.oid] as string });
      return await crypto.subtle.verify(name, k, buf(cert.signature), buf(cert.tbs));
    }
    if (sig.oid === PSS && key.oid === RSA_KEY) {
      const { hash, saltLength } = pssParams(sig.params);
      const k = await rsaKey(issuerSpki, { name: "RSA-PSS", hash });
      return await crypto.subtle.verify(
        { name: "RSA-PSS", saltLength },
        k,
        buf(cert.signature),
        buf(cert.tbs),
      );
    }
    if (ECDSA[sig.oid] && key.oid === EC_KEY && key.params) {
      const curve = CURVES[oidString(key.params.subarray(tlv(key.params, 0).body))];
      if (!curve) return false;
      const k = await crypto.subtle.importKey(
        "spki",
        buf(issuerSpki),
        { name: "ECDSA", namedCurve: curve.name },
        false,
        ["verify"],
      );
      const raw = ecdsaRaw(cert.signature, curve.size);
      return await crypto.subtle.verify(
        { name: "ECDSA", hash: ECDSA[sig.oid] as string },
        k,
        buf(raw),
        buf(cert.tbs),
      );
    }
    if (sig.oid === ED25519 && key.oid === ED25519) {
      const k = await crypto.subtle.importKey("spki", buf(issuerSpki), { name: "Ed25519" }, false, [
        "verify",
      ]);
      return await crypto.subtle.verify("Ed25519", k, buf(cert.signature), buf(cert.tbs));
    }
    return false;
  } catch {
    return false;
  }
}

function hostOf(name: string): string {
  return name.toLowerCase().replace(/\.$/, "");
}

export function nameMatches(presented: string, reference: string): boolean {
  const p = hostOf(presented);
  const r = hostOf(reference);
  if (p === r) return p.length > 0;
  if (!p.startsWith("*.")) return false;
  const rest = p.slice(2);
  if (rest.includes("*") || rest.split(".").length < 2) return false;
  const dot = r.indexOf(".");
  return dot > 0 && r.slice(dot + 1) === rest;
}

function presentedNames(leaf: Certificate): string[] {
  return leaf.dnsNames.length > 0 ? leaf.dnsNames : leaf.commonNames.map(hostOf);
}

function withinSubtree(name: string, base: string): boolean {
  const n = hostOf(name).replace(/^\*\./, "");
  const b = hostOf(base);
  if (b.startsWith(".")) return n.endsWith(b);
  return n === b || n.endsWith(`.${b}`);
}

export interface TrustAnchor {
  spki: Uint8Array;
  subject: Uint8Array | null;
}

export type ChainVerdict = { ok: true } | { ok: false; reason: string };

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

function usableAt(cert: Certificate, now: number): string | null {
  if (now < cert.notBefore) return "is not valid yet";
  if (now > cert.notAfter) return "has expired";
  if (cert.unknownCritical.length > 0)
    return `has an unknown critical extension (${cert.unknownCritical.join(", ")})`;
  return null;
}

export async function verifyChain(
  chain: Certificate[],
  anchors: TrustAnchor[],
  names: string[],
  now = Date.now(),
): Promise<ChainVerdict> {
  const leaf = chain[0];
  if (!leaf) return { ok: false, reason: "the server sent no certificate" };
  const leafProblem = usableAt(leaf, now);
  if (leafProblem) return { ok: false, reason: `the server certificate ${leafProblem}` };
  if (leaf.extKeyUsage && !leaf.extKeyUsage.some((u) => u === SERVER_AUTH || u === ANY_PURPOSE))
    return { ok: false, reason: "the server certificate is not allowed for TLS servers" };
  const presented = presentedNames(leaf);
  if (!presented.some((p) => names.some((n) => nameMatches(p, n)))) {
    return {
      ok: false,
      reason: `the server certificate names (${presented.join(", ") || "none"}) match none of ${names.join(", ")}`,
    };
  }

  let lastProblem = "the chain does not lead to a certificate or key in the TLSA records";
  const isAnchor = (c: Certificate) => anchors.some((a) => sameBytes(a.spki, c.spki));

  const search = async (path: Certificate[]): Promise<boolean> => {
    const current = path.at(-1) as Certificate;
    if (path.length === 1 && isAnchor(current)) return true;
    for (const a of anchors) {
      if (a.subject && !sameBytes(a.subject, current.issuer)) continue;
      if (await verifySignature(current, a.spki)) return constraintsHold(path);
    }
    if (path.length > MAX_DEPTH) return false;
    for (const issuer of chain) {
      if (path.includes(issuer) || !sameBytes(issuer.subject, current.issuer)) continue;
      const problem = issuerProblem(issuer, path, now);
      if (problem) {
        lastProblem = problem;
        continue;
      }
      if (!(await verifySignature(current, issuer.spki))) {
        lastProblem = "a certificate signature in the chain does not verify";
        continue;
      }
      if (await search([...path, issuer])) return true;
    }
    return false;
  };

  const constraintsHold = (path: Certificate[]): boolean => {
    for (const ca of path.slice(1)) {
      const nc = ca.nameConstraints;
      if (!nc) continue;
      if (nc.unsupported) {
        lastProblem = "the chain has name constraints that cannot be checked";
        return false;
      }
      for (const name of presented) {
        if (nc.excluded.some((b) => withinSubtree(name, b))) {
          lastProblem = `the name ${name} is excluded by the chain's name constraints`;
          return false;
        }
        if (nc.permitted.length > 0 && !nc.permitted.some((b) => withinSubtree(name, b))) {
          lastProblem = `the name ${name} is not permitted by the chain's name constraints`;
          return false;
        }
      }
    }
    return true;
  };

  if (await search([leaf])) return { ok: true };
  return { ok: false, reason: lastProblem };
}

function issuerProblem(issuer: Certificate, path: Certificate[], now: number): string | null {
  const problem = usableAt(issuer, now);
  if (problem) return `an intermediate certificate ${problem}`;
  if (!issuer.ca) return "an issuing certificate in the chain is not a CA";
  if (issuer.keyUsage !== null && (issuer.keyUsage & KEY_CERT_SIGN) === 0)
    return "an issuing certificate in the chain may not sign certificates";
  const below = path.length - 1;
  if (issuer.pathLen !== null && below > issuer.pathLen)
    return "the chain is longer than an issuing certificate allows";
  return null;
}
