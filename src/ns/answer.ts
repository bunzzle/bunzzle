import { Rcode, RRType } from "../dns/wire.ts";
import { inZone, UDP_LIMIT, type Zone } from "./zone.ts";

const CLASS_IN = 1;
const IXFR = 251;
const AXFR = 252;
const MAILB = 253;
const MAILA = 254;
const ANY = 255;
const OPCODE_NOTIFY = 4;
const OPCODE_UPDATE = 5;
const BADVERS = 16;
const NO_EDNS_LIMIT = 512;
const TCP_LIMIT = 65535;

export type Kind = "answer" | "negative" | "error";

export interface Reply {
  bytes: Uint8Array;
  truncated: Uint8Array | null;
  kind: Kind;
  rcode: number;
}

interface Query {
  id: number;
  flags: number;
  question: Uint8Array;
  name: string;
  nameLength: number;
  type: number;
  qclass: number;
  edns: { size: number; version: number } | null;
}

type Parsed = { ok: true; q: Query } | { ok: false; id: number; flags: number; rcode: number };

function parse(buf: Uint8Array): Parsed | null {
  if (buf.length < 12) return null;
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const id = v.getUint16(0);
  const flags = v.getUint16(2);
  if (flags & 0x8000) return null;
  const opcode = (flags >> 11) & 0xf;
  if (opcode !== 0) {
    const rcode =
      opcode === OPCODE_NOTIFY || opcode === OPCODE_UPDATE ? Rcode.REFUSED : Rcode.NOTIMP;
    return { ok: false, id, flags, rcode };
  }
  const formerr = { ok: false as const, id, flags, rcode: Rcode.FORMERR };
  const ar = v.getUint16(10);
  if (v.getUint16(4) !== 1 || v.getUint16(6) !== 0 || v.getUint16(8) !== 0 || ar > 1) {
    return formerr;
  }
  let p = 12;
  const labels: string[] = [];
  for (;;) {
    if (p >= buf.length) return formerr;
    const len = buf[p] as number;
    if (len & 0xc0) return formerr;
    p++;
    if (len === 0) break;
    if (p + len > buf.length) return formerr;
    let label = "";
    for (let i = 0; i < len; i++) {
      const c = buf[p + i] as number;
      label += String.fromCharCode(c >= 0x41 && c <= 0x5a ? c + 32 : c);
    }
    labels.push(label);
    p += len;
  }
  const nameLength = p - 12;
  if (nameLength > 255 || p + 4 > buf.length) return formerr;
  const type = v.getUint16(p);
  const qclass = v.getUint16(p + 2);
  const question = buf.subarray(12, p + 4);
  p += 4;
  let edns: Query["edns"] = null;
  if (ar === 1) {
    if (p + 11 > buf.length || buf[p] !== 0 || v.getUint16(p + 1) !== RRType.OPT) return formerr;
    const rdlen = v.getUint16(p + 9);
    edns = { size: v.getUint16(p + 3), version: buf[p + 6] as number };
    p += 11;
    const end = p + rdlen;
    if (end > buf.length) return formerr;
    while (p < end) {
      if (p + 4 > end) return formerr;
      p += 4 + v.getUint16(p + 2);
    }
    if (p !== end) return formerr;
  }
  if (p !== buf.length) return formerr;
  return {
    ok: true,
    q: { id, flags, question, name: labels.join("."), nameLength, type, qclass, edns },
  };
}

function opt(extended: number): number[] {
  return [0, 0, RRType.OPT, UDP_LIMIT >> 8, UDP_LIMIT & 0xff, extended, 0, 0, 0, 0, 0];
}

function message(
  q: Query,
  rcode: number,
  aa: boolean,
  answer: Uint8Array | null,
  answers: number,
  authority: Uint8Array | null,
  tc = false,
): Uint8Array {
  const extra = q.edns ? opt(rcode >> 4) : [];
  const size =
    12 + q.question.length + (answer?.length ?? 0) + (authority?.length ?? 0) + extra.length;
  const out = new Uint8Array(size);
  const v = new DataView(out.buffer);
  v.setUint16(0, q.id);
  v.setUint16(
    2,
    0x8000 | (aa ? 0x0400 : 0) | (tc ? 0x0200 : 0) | (q.flags & 0x0110) | (rcode & 0xf),
  );
  v.setUint16(4, 1);
  v.setUint16(6, answers);
  v.setUint16(8, authority ? 1 : 0);
  v.setUint16(10, q.edns ? 1 : 0);
  let at = 12;
  out.set(q.question, at);
  at += q.question.length;
  if (answer) {
    out.set(answer, at);
    at += answer.length;
  }
  if (authority) {
    out.set(authority, at);
    at += authority.length;
  }
  out.set(extra, at);
  return out;
}

function soaAuthority(q: Query, zone: Zone): Uint8Array {
  const offset = 12 + q.nameLength - zone.apexWire.length;
  const out = new Uint8Array(2 + zone.soa.length);
  out[0] = 0xc0 | (offset >> 8);
  out[1] = offset & 0xff;
  out.set(zone.soa, 2);
  return out;
}

function header(id: number, flags: number, rcode: number): Uint8Array {
  const out = new Uint8Array(12);
  const v = new DataView(out.buffer);
  v.setUint16(0, id);
  v.setUint16(2, 0x8000 | (flags & 0x7900) | (flags & 0x0110) | rcode);
  return out;
}

export function respond(
  buf: Uint8Array,
  apex: string,
  zone: Zone | null,
  tcp: boolean,
): Reply | null {
  const parsed = parse(buf);
  if (!parsed) return null;
  if (!parsed.ok) {
    if (parsed.rcode === Rcode.FORMERR && !tcp) return null;
    const bytes = header(parsed.id, parsed.flags, parsed.rcode);
    return { bytes, truncated: null, kind: "error", rcode: parsed.rcode };
  }
  const q = parsed.q;
  const done = (bytes: Uint8Array, kind: Kind, rcode: number): Reply => {
    const limit = tcp
      ? TCP_LIMIT
      : q.edns
        ? Math.min(Math.max(q.edns.size, NO_EDNS_LIMIT), UDP_LIMIT)
        : NO_EDNS_LIMIT;
    const truncated = message(q, rcode, rcode !== Rcode.REFUSED, null, 0, null, true);
    if (bytes.length > limit) return { bytes: truncated, truncated, kind, rcode };
    return { bytes, truncated: tcp ? null : truncated, kind, rcode };
  };
  const fail = (rcode: number, aa = false) =>
    done(message(q, rcode, aa, null, 0, null), "error", rcode);
  if (q.edns && q.edns.version !== 0) return fail(BADVERS);
  if (q.qclass !== CLASS_IN || !inZone(q.name, apex)) return fail(Rcode.REFUSED);
  if (q.type === AXFR || q.type === IXFR) return fail(Rcode.REFUSED);
  if (q.type === MAILA || q.type === MAILB) return fail(Rcode.NOTIMP, true);
  if (!zone) return fail(Rcode.SERVFAIL);
  const node = zone.names.get(q.name);
  if (!node) {
    return done(
      message(q, Rcode.NXDOMAIN, true, null, 0, soaAuthority(q, zone)),
      "negative",
      Rcode.NXDOMAIN,
    );
  }
  if (q.type === ANY) return done(message(q, 0, true, zone.hinfo, 1, null), "answer", 0);
  const set = node.get(q.type);
  if (!set) return done(message(q, 0, true, null, 0, soaAuthority(q, zone)), "negative", 0);
  return done(message(q, 0, true, set.bytes, set.count, null), "answer", 0);
}
