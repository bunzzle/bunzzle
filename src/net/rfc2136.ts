import type { Resolver } from "../dns/resolver.ts";
import type { CfRecord, CfResult } from "./cloudflare.ts";

export interface TsigKey {
  name: string;
  algorithm: "hmac-sha256" | "hmac-sha512";
  secret: Uint8Array;
}

export interface UpdateServer {
  host: string;
  port: number;
}

export type Exchange = (server: UpdateServer, message: Uint8Array) => Promise<Uint8Array>;

const TYPE = { SOA: 6, MX: 15, TXT: 16, TSIG: 250 } as const;
const CLASS = { IN: 1, NONE: 254, ANY: 255 } as const;
const RCODES: Record<number, string> = {
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
  6: "YXDOMAIN",
  7: "YXRRSET",
  8: "NXRRSET",
  9: "NOTAUTH",
  10: "NOTZONE",
  16: "BADSIG",
  17: "BADKEY",
  18: "BADTIME",
};
const FUDGE = 300;
const TTL = 300;

class Buf {
  readonly bytes: number[] = [];
  u8(n: number) {
    this.bytes.push(n & 0xff);
  }
  u16(n: number) {
    this.bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  u32(n: number) {
    this.bytes.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }
  u48(n: number) {
    this.u16(Math.floor(n / 2 ** 32));
    this.u32(n >>> 0);
  }
  raw(b: Uint8Array | number[]) {
    for (const x of b) this.bytes.push(x);
  }
  name(n: string) {
    const clean = n.toLowerCase().replace(/\.$/, "");
    if (clean) {
      for (const label of clean.split(".")) {
        const l = new TextEncoder().encode(label);
        if (l.length === 0 || l.length > 63) throw new Error(`bad DNS name: ${n}`);
        this.u8(l.length);
        this.raw(l);
      }
    }
    this.u8(0);
  }
}

function rdata(r: CfRecord): number[] {
  const b = new Buf();
  if (r.type === "MX") {
    b.u16(r.priority ?? 10);
    b.name(r.content);
  } else {
    const bytes = new TextEncoder().encode(r.content);
    for (let i = 0; i < bytes.length || i === 0; i += 255) {
      const part = bytes.subarray(i, i + 255);
      b.u8(part.length);
      b.raw(part);
    }
  }
  return b.bytes;
}

async function hmac(key: TsigKey, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    "raw",
    key.secret as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: key.algorithm === "hmac-sha512" ? "SHA-512" : "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as Uint8Array<ArrayBuffer>));
}

function tsigVariables(key: TsigKey, time: number, error = 0, fudge = FUDGE): number[] {
  const b = new Buf();
  b.name(key.name);
  b.u16(CLASS.ANY);
  b.u32(0);
  b.name(key.algorithm);
  b.u48(time);
  b.u16(fudge);
  b.u16(error);
  b.u16(0);
  return b.bytes;
}

export async function signedUpdate(
  zone: string,
  updates: { name: string; type: number; cls: number; ttl: number; data: number[] }[],
  key: TsigKey,
  id: number,
  time: number,
): Promise<{ message: Uint8Array; mac: Uint8Array }> {
  const b = new Buf();
  b.u16(id);
  b.u16(5 << 11);
  b.u16(1);
  b.u16(0);
  b.u16(updates.length);
  b.u16(0);
  b.name(zone);
  b.u16(TYPE.SOA);
  b.u16(CLASS.IN);
  for (const u of updates) {
    b.name(u.name);
    b.u16(u.type);
    b.u16(u.cls);
    b.u32(u.ttl);
    b.u16(u.data.length);
    b.raw(u.data);
  }
  const unsigned = Uint8Array.from(b.bytes);
  const mac = await hmac(key, Uint8Array.from([...unsigned, ...tsigVariables(key, time)]));
  const t = new Buf();
  t.name(key.algorithm);
  t.u48(time);
  t.u16(FUDGE);
  t.u16(mac.length);
  t.raw(mac);
  t.u16(id);
  t.u16(0);
  t.u16(0);
  b.name(key.name);
  b.u16(TYPE.TSIG);
  b.u16(CLASS.ANY);
  b.u32(0);
  b.u16(t.bytes.length);
  b.raw(t.bytes);
  const message = Uint8Array.from(b.bytes);
  new DataView(message.buffer).setUint16(10, 1);
  return { message, mac };
}

function skipName(m: Uint8Array, at: number): number {
  let p = at;
  for (let guard = 0; guard < 128; guard++) {
    const len = m[p];
    if (len === undefined) throw new Error("truncated DNS answer");
    if ((len & 0xc0) === 0xc0) return p + 2;
    if (len === 0) return p + 1;
    p += len + 1;
  }
  throw new Error("bad DNS name in answer");
}

export async function checkAnswer(
  answer: Uint8Array,
  id: number,
  key: TsigKey,
  requestMac: Uint8Array,
): Promise<number> {
  if (answer.length < 12) throw new Error("truncated DNS answer");
  const v = new DataView(answer.buffer, answer.byteOffset, answer.byteLength);
  if (v.getUint16(0) !== id) throw new Error("DNS answer does not match the request");
  const rcode = v.getUint16(2) & 0x0f;
  const counts = [v.getUint16(4), v.getUint16(6), v.getUint16(8), v.getUint16(10)];
  let p = 12;
  for (let i = 0; i < (counts[0] ?? 0); i++) p = skipName(answer, p) + 4;
  const rrs = (counts[1] ?? 0) + (counts[2] ?? 0) + (counts[3] ?? 0);
  let tsigAt = -1;
  for (let i = 0; i < rrs; i++) {
    const start = p;
    p = skipName(answer, p);
    const type = v.getUint16(p);
    const len = v.getUint16(p + 8);
    if (type === TYPE.TSIG && i === rrs - 1) tsigAt = start;
    p += 10 + len;
    if (p > answer.length) throw new Error("truncated DNS answer");
  }
  if (tsigAt < 0) {
    if (rcode !== 0) return rcode;
    throw new Error("the DNS server did not sign its answer");
  }
  const rd = skipName(answer, tsigAt) + 10;
  const afterAlg = skipName(answer, rd);
  const time = v.getUint16(afterAlg) * 2 ** 32 + v.getUint32(afterAlg + 2);
  const fudge = v.getUint16(afterAlg + 6);
  const macLen = v.getUint16(afterAlg + 8);
  const mac = answer.subarray(afterAlg + 10, afterAlg + 10 + macLen);
  const error = v.getUint16(afterAlg + 10 + macLen + 2);
  if (error !== 0) return error;
  const body = answer.slice(0, tsigAt);
  new DataView(body.buffer).setUint16(10, (counts[3] ?? 1) - 1);
  const prior = new Buf();
  prior.u16(requestMac.length);
  prior.raw(requestMac);
  const want = await hmac(
    key,
    Uint8Array.from([...prior.bytes, ...body, ...tsigVariables(key, time, 0, fudge)]),
  );
  if (want.length !== mac.length || !want.every((x, i) => x === mac[i])) {
    throw new Error("the DNS server's answer signature does not match the key");
  }
  return rcode;
}

export const tcpExchange: Exchange = (server, message) =>
  new Promise((resolve, reject) => {
    let buf = new Uint8Array(0);
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new Error("DNS update timed out"))), 15_000);
    Bun.connect({
      hostname: server.host,
      port: server.port,
      socket: {
        open(s) {
          const framed = new Uint8Array(message.length + 2);
          new DataView(framed.buffer).setUint16(0, message.length);
          framed.set(message, 2);
          s.write(framed);
        },
        data(s, chunk) {
          const next = new Uint8Array(buf.length + chunk.length);
          next.set(buf);
          next.set(chunk, buf.length);
          buf = next;
          if (buf.length >= 2) {
            const len = new DataView(buf.buffer).getUint16(0);
            if (buf.length >= len + 2) {
              done(() => resolve(buf.slice(2, len + 2)));
              s.end();
            }
          }
        },
        error(_s, err) {
          done(() => reject(new Error((err as Error | undefined)?.message ?? "socket error")));
        },
        close() {
          done(() => reject(new Error("the DNS server closed the connection")));
        },
      },
    }).catch((err: Error) => done(() => reject(err)));
  });

export class DnsUpdater {
  constructor(
    private readonly server: UpdateServer,
    private readonly key: TsigKey,
    private readonly resolver: Resolver,
    private readonly exchange: Exchange = tcpExchange,
    private readonly now: () => number = Date.now,
  ) {}

  async zoneFor(name: string): Promise<string> {
    const labels = name.toLowerCase().replace(/\.$/, "").split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join(".");
      const a = await this.resolver.query(candidate, "SOA");
      if (a.records.some((r) => r.type === "SOA" && r.name.toLowerCase() === candidate)) {
        return candidate;
      }
    }
    throw new Error(`no DNS zone found for ${name}`);
  }

  async #send(record: CfRecord, updates: Parameters<typeof signedUpdate>[1]): Promise<CfResult> {
    try {
      const zone = await this.zoneFor(record.name);
      const id = crypto.getRandomValues(new Uint16Array(1))[0] as number;
      const { message, mac } = await signedUpdate(
        zone,
        updates,
        this.key,
        id,
        Math.floor(this.now() / 1000),
      );
      const rcode = await checkAnswer(await this.exchange(this.server, message), id, this.key, mac);
      if (rcode !== 0) {
        return { ok: false, error: `DNS update refused: ${RCODES[rcode] ?? `rcode ${rcode}`}` };
      }
      return { ok: true, action: "updated" };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  upsert(record: CfRecord): Promise<CfResult> {
    const type = TYPE[record.type];
    return this.#send(record, [
      { name: record.name, type, cls: CLASS.ANY, ttl: 0, data: [] },
      { name: record.name, type, cls: CLASS.IN, ttl: TTL, data: rdata(record) },
    ]);
  }

  async remove(record: CfRecord): Promise<CfResult> {
    const r = await this.#send(record, [
      { name: record.name, type: TYPE[record.type], cls: CLASS.NONE, ttl: 0, data: rdata(record) },
    ]);
    return r.ok ? { ok: true, action: "removed" } : r;
  }
}
