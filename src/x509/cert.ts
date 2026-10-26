import { DerError, type Tlv, tlv } from "../asn1/der.ts";

export interface Algorithm {
  oid: string;
  params: Uint8Array | null;
}

export interface NameConstraints {
  permitted: string[];
  excluded: string[];
  unsupported: boolean;
}

export interface Certificate {
  der: Uint8Array;
  tbs: Uint8Array;
  signatureAlgorithm: Algorithm;
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: number;
  notAfter: number;
  spki: Uint8Array;
  ca: boolean;
  pathLen: number | null;
  keyUsage: number | null;
  extKeyUsage: string[] | null;
  dnsNames: string[];
  commonNames: string[];
  nameConstraints: NameConstraints | null;
  unknownCritical: string[];
}

export const KEY_CERT_SIGN = 1 << 5;

const KNOWN = new Set([
  "2.5.29.14",
  "2.5.29.15",
  "2.5.29.17",
  "2.5.29.19",
  "2.5.29.30",
  "2.5.29.32",
  "2.5.29.35",
  "2.5.29.37",
  "2.5.29.31",
  "1.3.6.1.5.5.7.1.1",
  "1.3.6.1.4.1.11129.2.4.2",
]);

function children(der: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = parent.body;
  while (at < parent.end) {
    const t = tlv(der, at);
    if (t.end > parent.end) throw new DerError("DER value overflows its parent");
    out.push(t);
    at = t.end;
  }
  return out;
}

function need(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (t?.tag !== tag) throw new DerError(`bad certificate: ${what}`);
  return t;
}

const raw = (der: Uint8Array, t: Tlv) => der.subarray(t.start, t.end);
const same = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);
const body = (der: Uint8Array, t: Tlv) => der.subarray(t.body, t.end);

export function oidString(bytes: Uint8Array): string {
  if (bytes.length === 0) throw new DerError("empty OID");
  const first = bytes[0] as number;
  const parts = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  let n = 0;
  for (let i = 1; i < bytes.length; i++) {
    const b = bytes[i] as number;
    n = n * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(n);
      n = 0;
    }
  }
  return parts.join(".");
}

export function algorithm(der: Uint8Array, t: Tlv): Algorithm {
  const [id, params] = children(der, need(t, 0x30, "algorithm"));
  const oid = oidString(body(der, need(id, 0x06, "algorithm OID")));
  return { oid, params: params && params.tag !== 0x05 ? raw(der, params) : null };
}

function time(der: Uint8Array, t: Tlv): number {
  const s = new TextDecoder().decode(body(der, t));
  const m =
    t.tag === 0x17
      ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
      : t.tag === 0x18
        ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)
        : null;
  if (!m) throw new DerError("bad certificate time");
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

const utf8 = new TextDecoder("utf-8", { fatal: true });
const latin1 = new TextDecoder("latin1");

function text(der: Uint8Array, t: Tlv): string | null {
  if (t.tag === 0x0c) {
    try {
      return utf8.decode(body(der, t));
    } catch {
      throw new DerError("bad certificate: UTF8String is not UTF-8");
    }
  }
  if (t.tag === 0x13 || t.tag === 0x16 || t.tag === 0x14) return latin1.decode(body(der, t));
  return null;
}

function commonNames(der: Uint8Array, name: Tlv): string[] {
  const out: string[] = [];
  for (const rdn of children(der, name)) {
    for (const atv of children(der, need(rdn, 0x31, "name"))) {
      const [type, value] = children(der, need(atv, 0x30, "name attribute"));
      if (oidString(body(der, need(type, 0x06, "name attribute"))) !== "2.5.4.3" || !value)
        continue;
      const s = text(der, value);
      if (s !== null) out.push(s);
    }
  }
  return out;
}

function ascii(der: Uint8Array, t: Tlv): string {
  return String.fromCharCode(...body(der, t)).toLowerCase();
}

function constraints(der: Uint8Array, t: Tlv): NameConstraints {
  const out: NameConstraints = { permitted: [], excluded: [], unsupported: false };
  for (const part of children(der, need(t, 0x30, "name constraints"))) {
    const list = part.tag === 0xa0 ? out.permitted : part.tag === 0xa1 ? out.excluded : null;
    if (!list) {
      out.unsupported = true;
      continue;
    }
    for (const subtree of children(der, part)) {
      const [base, ...rest] = children(der, need(subtree, 0x30, "subtree"));
      if (base?.tag === 0x82 && rest.length === 0) list.push(ascii(der, base));
      else out.unsupported = true;
    }
  }
  return out;
}

function bitsOf(byte: number): number {
  let out = 0;
  for (let i = 0; i < 8; i++) if (byte & (0x80 >> i)) out |= 1 << i;
  return out;
}

export function parseCertificate(der: Uint8Array): Certificate {
  const top = need(tlv(der, 0), 0x30, "certificate");
  if (top.end !== der.length) throw new DerError("bad certificate: trailing data");
  const [tbsT, algT, sigT] = children(der, top);
  const tbs = need(tbsT, 0x30, "tbsCertificate");
  const sig = body(der, need(sigT, 0x03, "signature"));
  if (sig[0] !== 0) throw new DerError("bad certificate: signature has unused bits");

  const fields = children(der, tbs);
  if (fields[0]?.tag === 0xa0) fields.shift();
  const [, innerAlg, issuer, validity, subject, spki, ...rest] = fields;
  const outer = raw(der, need(algT, 0x30, "signature algorithm"));
  if (!innerAlg || !same(raw(der, innerAlg), outer))
    throw new DerError("bad certificate: signature algorithms differ");
  const [nb, na] = children(der, need(validity, 0x30, "validity"));
  if (!nb || !na) throw new DerError("bad certificate: validity");

  const cert: Certificate = {
    der,
    tbs: raw(der, tbs),
    signatureAlgorithm: algorithm(der, algT as Tlv),
    signature: sig.subarray(1),
    issuer: raw(der, need(issuer, 0x30, "issuer")),
    subject: raw(der, need(subject, 0x30, "subject")),
    notBefore: time(der, nb),
    notAfter: time(der, na),
    spki: raw(der, need(spki, 0x30, "subjectPublicKeyInfo")),
    ca: false,
    pathLen: null,
    keyUsage: null,
    extKeyUsage: null,
    dnsNames: [],
    commonNames: commonNames(der, subject as Tlv),
    nameConstraints: null,
    unknownCritical: [],
  };

  const extWrap = rest.find((t) => t.tag === 0xa3);
  if (!extWrap) return cert;
  const [exts] = children(der, extWrap);
  for (const ext of children(der, need(exts, 0x30, "extensions"))) {
    const parts = children(der, need(ext, 0x30, "extension"));
    const id = oidString(body(der, need(parts[0], 0x06, "extension OID")));
    const critical = parts[1]?.tag === 0x01 && der[parts[1].body] !== 0;
    const valueT = need(parts.at(-1), 0x04, "extension value");
    const value = tlv(der, valueT.body);
    if (value.end !== valueT.end) throw new DerError("bad certificate: extension value");
    if (id === "2.5.29.19") {
      const [flag, len] = children(der, need(value, 0x30, "basic constraints"));
      cert.ca = flag?.tag === 0x01 && der[flag.body] !== 0;
      const n = flag?.tag === 0x02 ? flag : len;
      if (n?.tag === 0x02) {
        const b = body(der, n);
        if (b.length > 2 || ((b[0] ?? 0) & 0x80) !== 0) throw new DerError("bad pathLen");
        cert.pathLen = b.reduce((a, x) => a * 256 + x, 0);
      }
    } else if (id === "2.5.29.15") {
      const b = body(der, need(value, 0x03, "key usage"));
      cert.keyUsage = bitsOf(b[1] ?? 0) | (bitsOf(b[2] ?? 0) << 8);
    } else if (id === "2.5.29.37") {
      cert.extKeyUsage = children(der, need(value, 0x30, "extended key usage")).map((t) =>
        oidString(body(der, need(t, 0x06, "key purpose"))),
      );
    } else if (id === "2.5.29.17") {
      for (const n of children(der, need(value, 0x30, "subject alternative name"))) {
        if (n.tag === 0x82) cert.dnsNames.push(ascii(der, n));
      }
    } else if (id === "2.5.29.30") {
      cert.nameConstraints = constraints(der, value);
    } else if (critical && !KNOWN.has(id)) {
      cert.unknownCritical.push(id);
    }
  }
  return cert;
}
