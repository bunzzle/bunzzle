export const RRType = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  OPT: 41,
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

export interface SoaData {
  mname: string;
  minimum: number;
}

export type RecordData =
  | { type: "A"; address: string }
  | { type: "AAAA"; address: string }
  | { type: "CNAME"; target: string }
  | { type: "NS"; target: string }
  | { type: "MX"; mx: MxData }
  | { type: "TXT"; strings: string[] }
  | { type: "SOA"; soa: SoaData }
  | { type: "OTHER"; code: number };

export type ResourceRecord = { name: string; ttl: number } & RecordData;

export interface DnsMessage {
  id: number;
  rcode: number;
  truncated: boolean;
  authenticated: boolean;
  question: { name: string; type: number } | null;
  answers: ResourceRecord[];
  authority: ResourceRecord[];
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

export function encodeQuery(id: number, name: string, type: number): Uint8Array {
  const labels = name.split(".");
  const nameLen = labels.reduce((n, l) => n + l.length + 1, 1);
  const out = new Uint8Array(12 + nameLen + 4 + 11);
  const v = new DataView(out.buffer);
  v.setUint16(0, id);
  v.setUint16(2, 0x0120);
  v.setUint16(4, 1);
  v.setUint16(10, 1);
  let p = 12;
  for (const l of labels) {
    out[p++] = l.length;
    for (let i = 0; i < l.length; i++) out[p++] = l.charCodeAt(i);
  }
  out[p++] = 0;
  v.setUint16(p, type);
  v.setUint16(p + 2, 1);
  p += 4;
  out[p++] = 0;
  v.setUint16(p, RRType.OPT);
  v.setUint16(p + 2, 1232);
  v.setUint32(p + 4, 0);
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
    const labels: string[] = [];
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
      for (let i = 0; i < len; i++) label += String.fromCharCode(this.buf[pos + i] as number);
      labels.push(label.toLowerCase());
      total += len + 1;
      if (total > 255) throw new DnsWireError("name too long");
      pos += len;
    }
    if (!jumped) this.pos = pos;
    return labels.join(".");
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

function readRecord(r: Reader): ResourceRecord {
  const name = r.name();
  const type = r.u16();
  r.u16();
  const ttl = r.u32() & 0x7fffffff;
  const len = r.u16();
  r.need(len);
  const end = r.pos + len;
  const base = { name, ttl };
  let rec: ResourceRecord;
  switch (type) {
    case RRType.A: {
      if (len !== 4) throw new DnsWireError("bad A record");
      rec = { ...base, type: "A", address: Array.from(r.bytes(4)).join(".") };
      break;
    }
    case RRType.AAAA: {
      if (len !== 16) throw new DnsWireError("bad AAAA record");
      rec = { ...base, type: "AAAA", address: formatIPv6(r.bytes(16)) };
      break;
    }
    case RRType.CNAME:
      rec = { ...base, type: "CNAME", target: r.name() };
      break;
    case RRType.NS:
      rec = { ...base, type: "NS", target: r.name() };
      break;
    case RRType.MX: {
      const preference = r.u16();
      rec = { ...base, type: "MX", mx: { preference, exchange: r.name() } };
      break;
    }
    case RRType.TXT: {
      const strings: string[] = [];
      const dec = new TextDecoder();
      while (r.pos < end) strings.push(dec.decode(r.bytes(r.u8())));
      rec = { ...base, type: "TXT", strings };
      break;
    }
    case RRType.SOA: {
      const mname = r.name();
      r.name();
      r.bytes(16);
      rec = { ...base, type: "SOA", soa: { mname, minimum: r.u32() } };
      break;
    }
    default:
      rec = { ...base, type: "OTHER", code: type };
  }
  if (r.pos > end) throw new DnsWireError("record overflows its length");
  r.pos = end;
  return rec;
}

export function decodeMessage(buf: Uint8Array): DnsMessage {
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  if ((flags & 0x8000) === 0) throw new DnsWireError("not a response");
  const qd = r.u16();
  const an = r.u16();
  const ns = r.u16();
  r.u16();
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
  return {
    id,
    rcode: flags & 0x000f,
    truncated,
    authenticated: (flags & 0x0020) !== 0,
    question,
    answers,
    authority,
  };
}
