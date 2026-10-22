export const RRType = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DNAME: 39,
  OPT: 41,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  TLSA: 52,
} as const;

export type RRTypeName = keyof typeof RRType;

export const Rcode = {
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
} as const;

export interface MxData {
  preference: number;
  exchange: string;
}

export interface TlsaData {
  usage: number;
  selector: number;
  matching: number;
  data: Uint8Array;
}

export interface DnskeyData {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: Uint8Array;
  keyTag: number;
}

export interface DsData {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Uint8Array;
}

export interface RrsigData {
  typeCovered: number;
  algorithm: number;
  labels: number;
  originalTtl: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signer: string;
  signature: Uint8Array;
}

export interface NsecData {
  next: string;
  types: number[];
}

export interface Nsec3Data {
  hashAlgorithm: number;
  flags: number;
  iterations: number;
  salt: Uint8Array;
  nextHashed: Uint8Array;
  types: number[];
}

export interface SoaData {
  mname: string;
  serial: number;
  minimum: number;
}

export type RecordData =
  | { type: "A"; address: string }
  | { type: "AAAA"; address: string }
  | { type: "CNAME"; target: string }
  | { type: "DNAME"; target: string }
  | { type: "NS"; target: string }
  | { type: "PTR"; target: string }
  | { type: "MX"; mx: MxData }
  | { type: "TXT"; strings: string[] }
  | { type: "SOA"; soa: SoaData }
  | { type: "TLSA"; tlsa: TlsaData }
  | { type: "DNSKEY"; dnskey: DnskeyData }
  | { type: "DS"; ds: DsData }
  | { type: "RRSIG"; rrsig: RrsigData }
  | { type: "NSEC"; nsec: NsecData }
  | { type: "NSEC3"; nsec3: Nsec3Data }
  | { type: "OTHER"; code: number };

export type ResourceRecord = {
  name: string;
  ttl: number;
  rrtype: number;
  rdata: Uint8Array;
} & RecordData;

export interface DnsMessage {
  id: number;
  rcode: number;
  truncated: boolean;
  authenticated: boolean;
  authoritative?: boolean;
  question: { name: string; type: number } | null;
  answers: ResourceRecord[];
  authority: ResourceRecord[];
  additional?: ResourceRecord[];
}

export class DnsWireError extends Error {}

const MAX_NAME = 253;
const MAX_LABEL = 63;

export function normalizeName(name: string): string {
  let n = name.trim().toLowerCase();
  if (n.endsWith(".")) n = n.slice(0, -1);
  if (/[\u0080-\uffff]/.test(n)) {
    try {
      n = new URL(`http://${n}`).hostname;
    } catch {
      throw new DnsWireError(`invalid domain name: ${name}`);
    }
  }
  if (n.length === 0 || n.length > MAX_NAME) throw new DnsWireError(`invalid domain name: ${name}`);
  for (const label of n.split(".")) {
    if (label.length === 0 || label.length > MAX_LABEL || !/^[a-z0-9_-]+$/.test(label)) {
      throw new DnsWireError(`invalid domain name: ${name}`);
    }
  }
  return n;
}

export function nameToWire(name: string): Uint8Array {
  const labels = name === "" || name === "." ? [] : name.replace(/\.$/, "").split(".");
  const out = new Uint8Array(labels.reduce((n, l) => n + l.length + 1, 1));
  let p = 0;
  for (const l of labels) {
    out[p++] = l.length;
    for (let i = 0; i < l.length; i++) out[p++] = l.charCodeAt(i);
  }
  out[p] = 0;
  return out;
}

export function keyTag(rdata: Uint8Array): number {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++)
    ac += i & 1 ? (rdata[i] as number) : (rdata[i] as number) << 8;
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

export function encodeQuery(id: number, name: string, type: number, dnssec = false): Uint8Array {
  const qname = nameToWire(name);
  const out = new Uint8Array(12 + qname.length + 4 + 11);
  const v = new DataView(out.buffer);
  v.setUint16(0, id);
  v.setUint16(2, dnssec ? 0x0130 : 0x0120);
  v.setUint16(4, 1);
  v.setUint16(10, 1);
  out.set(qname, 12);
  let p = 12 + qname.length;
  v.setUint16(p, type);
  v.setUint16(p + 2, 1);
  p += 4;
  out[p++] = 0;
  v.setUint16(p, RRType.OPT);
  v.setUint16(p + 2, 1232);
  v.setUint32(p + 4, dnssec ? 0x8000 : 0);
  v.setUint16(p + 8, 0);
  return out;
}

class Reader {
  readonly view: DataView;
  pos = 0;

  constructor(readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  need(n: number) {
    if (this.pos + n > this.buf.length) throw new DnsWireError("truncated message");
  }

  u8(): number {
    this.need(1);
    return this.view.getUint8(this.pos++);
  }

  u16(): number {
    this.need(2);
    const x = this.view.getUint16(this.pos);
    this.pos += 2;
    return x;
  }

  u32(): number {
    this.need(4);
    const x = this.view.getUint32(this.pos);
    this.pos += 4;
    return x;
  }

  bytes(n: number): Uint8Array {
    this.need(n);
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }

  name(): string {
    return this.wireName(true).text;
  }

  wireName(lower: boolean): { text: string; wire: Uint8Array } {
    const labels: string[] = [];
    const wire: number[] = [];
    let pos = this.pos;
    let jumped = false;
    let jumps = 0;
    let total = 0;
    for (;;) {
      if (pos >= this.buf.length) throw new DnsWireError("truncated name");
      const len = this.buf[pos] as number;
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= this.buf.length) throw new DnsWireError("truncated pointer");
        if (++jumps > 64) throw new DnsWireError("compression loop");
        const target = ((len & 0x3f) << 8) | (this.buf[pos + 1] as number);
        if (!jumped) this.pos = pos + 2;
        jumped = true;
        pos = target;
        continue;
      }
      if (len & 0xc0) throw new DnsWireError("unsupported label type");
      pos++;
      if (len === 0) break;
      if (pos + len > this.buf.length) throw new DnsWireError("truncated label");
      let label = "";
      wire.push(len);
      for (let i = 0; i < len; i++) {
        const c = this.buf[pos + i] as number;
        label += String.fromCharCode(c);
        wire.push(lower && c >= 0x41 && c <= 0x5a ? c + 32 : c);
      }
      labels.push(label.toLowerCase());
      total += len + 1;
      if (total > 255) throw new DnsWireError("name too long");
      pos += len;
    }
    if (!jumped) this.pos = pos;
    wire.push(0);
    return { text: labels.join("."), wire: Uint8Array.from(wire) };
  }
}

function formatIPv6(b: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i] as number) << 8) | (b[i + 1] as number));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i > 1) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(":");
  const head = hex.slice(0, bestStart).join(":");
  const tail = hex.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}

function concat(...parts: (Uint8Array | number[])[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function typeBitmap(bits: Uint8Array): number[] {
  const types: number[] = [];
  let last = -1;
  for (let at = 0; at < bits.length; ) {
    const win = bits[at] as number;
    const len = bits[at + 1] ?? 0;
    if (len < 1 || len > 32 || win <= last || at + 2 + len > bits.length) {
      throw new DnsWireError("bad type bitmap");
    }
    last = win;
    for (let i = 0; i < len; i++) {
      const byte = bits[at + 2 + i] as number;
      for (let b = 0; b < 8; b++) if (byte & (0x80 >> b)) types.push(win * 256 + i * 8 + b);
    }
    at += 2 + len;
  }
  return types;
}

function readData(r: Reader, type: number, len: number, end: number): [RecordData, Uint8Array] {
  const raw = () => r.buf.slice(end - len, end);
  switch (type) {
    case RRType.A:
      if (len !== 4) throw new DnsWireError("bad A record");
      return [{ type: "A", address: Array.from(r.bytes(4)).join(".") }, raw()];
    case RRType.AAAA:
      if (len !== 16) throw new DnsWireError("bad AAAA record");
      return [{ type: "AAAA", address: formatIPv6(r.bytes(16)) }, raw()];
    case RRType.CNAME:
    case RRType.NS:
    case RRType.PTR:
    case RRType.DNAME: {
      const n = r.wireName(true);
      const kind =
        type === RRType.CNAME
          ? "CNAME"
          : type === RRType.DNAME
            ? "DNAME"
            : type === RRType.NS
              ? "NS"
              : "PTR";
      return [{ type: kind, target: n.text }, n.wire];
    }
    case RRType.MX: {
      const head = r.bytes(2);
      const n = r.wireName(true);
      const preference = ((head[0] as number) << 8) | (head[1] as number);
      return [{ type: "MX", mx: { preference, exchange: n.text } }, concat(head, n.wire)];
    }
    case RRType.SRV: {
      const head = r.bytes(6);
      return [{ type: "OTHER", code: type }, concat(head, r.wireName(true).wire)];
    }
    case RRType.TXT: {
      const strings: string[] = [];
      const dec = new TextDecoder();
      while (r.pos < end) strings.push(dec.decode(r.bytes(r.u8())));
      return [{ type: "TXT", strings }, raw()];
    }
    case RRType.SOA: {
      const mname = r.wireName(true);
      const rname = r.wireName(true);
      const fixed = r.bytes(20);
      const view = new DataView(fixed.buffer, fixed.byteOffset, 20);
      return [
        {
          type: "SOA",
          soa: { mname: mname.text, serial: view.getUint32(0), minimum: view.getUint32(16) },
        },
        concat(mname.wire, rname.wire, fixed),
      ];
    }
    case RRType.TLSA: {
      if (len < 3) throw new DnsWireError("bad TLSA record");
      const usage = r.u8();
      const selector = r.u8();
      const matching = r.u8();
      const data = new Uint8Array(r.bytes(len - 3));
      return [{ type: "TLSA", tlsa: { usage, selector, matching, data } }, raw()];
    }
    case RRType.DNSKEY: {
      if (len < 5) throw new DnsWireError("bad DNSKEY record");
      const flags = r.u16();
      const protocol = r.u8();
      const algorithm = r.u8();
      const publicKey = new Uint8Array(r.bytes(len - 4));
      const rdata = raw();
      return [
        {
          type: "DNSKEY",
          dnskey: { flags, protocol, algorithm, publicKey, keyTag: keyTag(rdata) },
        },
        rdata,
      ];
    }
    case RRType.DS: {
      if (len < 5) throw new DnsWireError("bad DS record");
      const tag = r.u16();
      const algorithm = r.u8();
      const digestType = r.u8();
      const digest = new Uint8Array(r.bytes(len - 4));
      return [{ type: "DS", ds: { keyTag: tag, algorithm, digestType, digest } }, raw()];
    }
    case RRType.RRSIG: {
      if (len < 19) throw new DnsWireError("bad RRSIG record");
      const fixed = r.bytes(18);
      const v = new DataView(fixed.buffer, fixed.byteOffset, 18);
      const signer = r.wireName(true);
      if (r.pos > end) throw new DnsWireError("bad RRSIG record");
      const signature = new Uint8Array(r.bytes(end - r.pos));
      return [
        {
          type: "RRSIG",
          rrsig: {
            typeCovered: v.getUint16(0),
            algorithm: v.getUint8(2),
            labels: v.getUint8(3),
            originalTtl: v.getUint32(4),
            expiration: v.getUint32(8),
            inception: v.getUint32(12),
            keyTag: v.getUint16(16),
            signer: signer.text,
            signature,
          },
        },
        concat(fixed, signer.wire, signature),
      ];
    }
    case RRType.NSEC: {
      const next = r.wireName(false);
      if (r.pos > end) throw new DnsWireError("bad NSEC record");
      const bits = r.bytes(end - r.pos);
      return [
        { type: "NSEC", nsec: { next: next.text, types: typeBitmap(bits) } },
        concat(next.wire, bits),
      ];
    }
    case RRType.NSEC3: {
      const hashAlgorithm = r.u8();
      const flags = r.u8();
      const iterations = r.u16();
      const salt = new Uint8Array(r.bytes(r.u8()));
      const nextHashed = new Uint8Array(r.bytes(r.u8()));
      if (r.pos > end) throw new DnsWireError("bad NSEC3 record");
      const types = typeBitmap(r.bytes(end - r.pos));
      return [
        { type: "NSEC3", nsec3: { hashAlgorithm, flags, iterations, salt, nextHashed, types } },
        raw(),
      ];
    }
    default:
      return [{ type: "OTHER", code: type }, raw()];
  }
}

function readRecord(r: Reader): ResourceRecord {
  const name = r.name();
  const rrtype = r.u16();
  r.u16();
  const ttl = r.u32() & 0x7fffffff;
  const len = r.u16();
  r.need(len);
  const end = r.pos + len;
  const [data, rdata] = readData(r, rrtype, len, end);
  if (r.pos > end) throw new DnsWireError("record overflows its length");
  r.pos = end;
  return { name, ttl, rrtype, rdata, ...data };
}

export function decodeMessage(buf: Uint8Array): DnsMessage {
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  if ((flags & 0x8000) === 0) throw new DnsWireError("not a response");
  const qd = r.u16();
  const an = r.u16();
  const ns = r.u16();
  const ar = r.u16();
  let question: DnsMessage["question"] = null;
  for (let i = 0; i < qd; i++) {
    const name = r.name();
    const type = r.u16();
    r.u16();
    if (i === 0) question = { name, type };
  }
  const truncated = (flags & 0x0200) !== 0;
  const answers: ResourceRecord[] = [];
  const authority: ResourceRecord[] = [];
  try {
    for (let i = 0; i < an; i++) answers.push(readRecord(r));
    for (let i = 0; i < ns; i++) authority.push(readRecord(r));
  } catch (err) {
    if (!truncated) throw err;
  }
  const additional: ResourceRecord[] = [];
  try {
    for (let i = 0; i < ar; i++) additional.push(readRecord(r));
  } catch {}
  return {
    id,
    rcode: flags & 0x000f,
    truncated,
    authenticated: (flags & 0x0020) !== 0,
    authoritative: (flags & 0x0400) !== 0,
    question,
    answers,
    authority,
    additional,
  };
}
