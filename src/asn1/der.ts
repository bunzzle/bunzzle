export class DerError extends Error {}

export interface Tlv {
  tag: number;
  start: number;
  body: number;
  end: number;
}

export function tlv(der: Uint8Array, at: number): Tlv {
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

function tbsFields(cert: Uint8Array): Tlv[] {
  const certificate = tlv(cert, 0);
  const tbs = tlv(cert, certificate.body);
  const out: Tlv[] = [];
  let at = tbs.body;
  while (at < tbs.end && out.length < 12) {
    const f = tlv(cert, at);
    out.push(f);
    at = f.end;
  }
  if (out[0]?.tag === 0xa0) out.shift();
  return out;
}

export function spkiOf(cert: Uint8Array): Uint8Array {
  const f = tbsFields(cert)[5];
  if (f?.tag !== 0x30) throw new DerError("no subjectPublicKeyInfo");
  return cert.slice(f.start, f.end);
}

function readTime(der: Uint8Array, t: Tlv): number {
  const s = new TextDecoder().decode(der.subarray(t.body, t.end));
  const m =
    t.tag === 0x17
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
      : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) throw new DerError("bad certificate time");
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

export function notAfter(cert: Uint8Array): number {
  const validity = tbsFields(cert)[3];
  if (validity?.tag !== 0x30) throw new DerError("no validity");
  const notBefore = tlv(cert, validity.body);
  return readTime(cert, tlv(cert, notBefore.end));
}

function len(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) bytes.unshift(x & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

export function node(tag: number, ...parts: (number[] | Uint8Array)[]): number[] {
  const body = parts.flatMap((p) => Array.from(p));
  return [tag, ...len(body.length), ...body];
}

export const seq = (...parts: (number[] | Uint8Array)[]) => node(0x30, ...parts);
export const set = (...parts: (number[] | Uint8Array)[]) => node(0x31, ...parts);

export function integer(bytes: Uint8Array | number[]): number[] {
  let b = Array.from(bytes);
  while (b.length > 1 && b[0] === 0 && ((b[1] as number) & 0x80) === 0) b = b.slice(1);
  if (((b[0] ?? 0) & 0x80) !== 0) b = [0, ...b];
  return node(0x02, b);
}

export function oid(dotted: string): number[] {
  const [a = 0, c = 0, ...rest] = dotted.split(".").map(Number);
  const out = [a * 40 + c];
  for (const n of rest) {
    const chunk: number[] = [];
    let x = n;
    do {
      chunk.unshift(x & 0x7f);
      x = Math.floor(x / 128);
    } while (x > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] = (chunk[i] as number) | 0x80;
    out.push(...chunk);
  }
  return node(0x06, out);
}

export const utf8 = (s: string) => node(0x0c, new TextEncoder().encode(s));
export const octets = (b: number[] | Uint8Array) => node(0x04, b);
export const bits = (b: number[] | Uint8Array) => node(0x03, [0], b);

export function ecdsaSignatureDer(raw: Uint8Array): number[] {
  const half = raw.length / 2;
  return seq(integer(raw.subarray(0, half)), integer(raw.subarray(half)));
}

export function pem(label: string, der: Uint8Array | number[]): string {
  const lines =
    Uint8Array.from(der)
      .toBase64()
      .match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export function fromPem(text: string): Uint8Array[] {
  return [...text.matchAll(/-----BEGIN ([A-Z ]+)-----([^-]+)-----END \1-----/g)].map((m) =>
    Uint8Array.fromBase64((m[2] as string).replace(/\s+/g, "")),
  );
}
