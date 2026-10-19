import type { TlsaData } from "../dns/wire.ts";

export class DerError extends Error {}

interface Tlv {
  tag: number;
  start: number;
  body: number;
  end: number;
}

function tlv(der: Uint8Array, at: number): Tlv {
  if (at + 2 > der.length) throw new DerError("truncated DER");
  const tag = der[at] as number;
  let len = der[at + 1] as number;
  let body = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || body + n > der.length) throw new DerError("bad DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (der[body + i] as number);
    body += n;
  }
  const end = body + len;
  if (end > der.length) throw new DerError("DER value overflows");
  return { tag, start: at, body, end };
}

export function spkiOf(cert: Uint8Array): Uint8Array {
  const certificate = tlv(cert, 0);
  const tbs = tlv(cert, certificate.body);
  let at = tbs.body;
  let field = tlv(cert, at);
  if (field.tag === 0xa0) {
    at = field.end;
    field = tlv(cert, at);
  }
  for (let i = 0; i < 5; i++) {
    at = field.end;
    field = tlv(cert, at);
  }
  if (field.tag !== 0x30) throw new DerError("no subjectPublicKeyInfo");
  return cert.slice(field.start, field.end);
}

export function usable(records: TlsaData[]): TlsaData[] {
  return records.filter(
    (r) =>
      (r.usage === 3 && r.selector <= 1 && r.matching <= 2) ||
      (r.usage === 2 && r.selector === 0 && r.matching === 0),
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

export function trustAnchors(records: TlsaData[]): string | null {
  const full = records.filter((r) => r.usage === 2 && r.selector === 0 && r.matching === 0);
  if (full.length === 0) return null;
  return full
    .map((r) => {
      const b64 = r.data.toBase64().replace(/.{64}/g, "$&\n");
      return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
    })
    .join("");
}

export type DaneVerdict =
  | { ok: true; how: "dane-ee" | "dane-ta" | "unauthenticated" }
  | { ok: false; reason: string };

export function verifyDane(
  records: TlsaData[],
  leaf: Uint8Array | null,
  anchoredAndAuthorized: boolean,
): DaneVerdict {
  const list = usable(records);
  if (list.length === 0) return { ok: true, how: "unauthenticated" };
  if (leaf && list.some((r) => r.usage === 3 && matches(r, leaf)))
    return { ok: true, how: "dane-ee" };
  if (anchoredAndAuthorized) return { ok: true, how: "dane-ta" };
  return { ok: false, reason: "the certificate matches none of its TLSA records" };
}

export function presentation(r: TlsaData): string {
  return `${r.usage} ${r.selector} ${r.matching} ${r.data.toHex()}`;
}
