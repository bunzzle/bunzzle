import { spkiOf } from "../asn1/der.ts";
import type { TlsaData } from "../dns/wire.ts";

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
