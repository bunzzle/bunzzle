import { spkiOf } from "../asn1/der.ts";
import type { TlsaData } from "../dns/wire.ts";
import { type Certificate, parseCertificate } from "../x509/cert.ts";
import { type TrustAnchor, verifyChain } from "../x509/verify.ts";

export function usable(records: TlsaData[]): TlsaData[] {
  return records.filter(
    (r) => (r.usage === 3 || r.usage === 2) && r.selector <= 1 && r.matching <= 2,
  );
}

function digest(matching: number, data: Uint8Array): Uint8Array {
  if (matching === 0) return data;
  const h = new Bun.CryptoHasher(matching === 1 ? "sha256" : "sha512");
  h.update(data);
  return new Uint8Array(h.digest());
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

export function matches(record: TlsaData, cert: Uint8Array): boolean {
  let subject: Uint8Array;
  try {
    subject = record.selector === 0 ? cert : spkiOf(cert);
  } catch {
    return false;
  }
  return equal(digest(record.matching, subject), record.data);
}

function parsed(der: Uint8Array): Certificate | null {
  try {
    return parseCertificate(der);
  } catch {
    return null;
  }
}

function anchorsFor(records: TlsaData[], chain: Certificate[]): TrustAnchor[] {
  const out: TrustAnchor[] = [];
  for (const r of records) {
    for (const c of chain) {
      if (matches(r, c.der)) out.push({ spki: c.spki, subject: c.subject });
    }
    if (r.matching !== 0) continue;
    if (r.selector === 0) {
      const c = parsed(r.data);
      if (c) out.push({ spki: c.spki, subject: c.subject });
    } else {
      out.push({ spki: r.data, subject: null });
    }
  }
  return out;
}

export type DaneVerdict =
  | { ok: true; how: "dane-ee" | "dane-ta" | "unauthenticated" }
  | { ok: false; reason: string };

export async function verifyDane(
  records: TlsaData[],
  chain: Uint8Array[],
  names: string[],
  now = Date.now(),
): Promise<DaneVerdict> {
  const list = usable(records);
  if (list.length === 0) return { ok: true, how: "unauthenticated" };
  const leaf = chain[0];
  if (!leaf) return { ok: false, reason: "the server sent no certificate" };
  if (list.some((r) => r.usage === 3 && matches(r, leaf))) return { ok: true, how: "dane-ee" };

  const ta = list.filter((r) => r.usage === 2);
  if (ta.length === 0)
    return { ok: false, reason: "the certificate matches none of its TLSA records" };
  const certs = chain.map(parsed);
  if (certs[0] === null) return { ok: false, reason: "the server certificate cannot be read" };
  const readable = certs.filter((c): c is Certificate => c !== null);
  const anchors = anchorsFor(ta, readable);
  if (anchors.length === 0)
    return { ok: false, reason: "no certificate in the chain matches its DANE-TA records" };
  const verdict = await verifyChain(readable, anchors, names, now);
  return verdict.ok ? { ok: true, how: "dane-ta" } : verdict;
}

export function presentation(r: TlsaData): string {
  return `${r.usage} ${r.selector} ${r.matching} ${r.data.toHex()}`;
}
