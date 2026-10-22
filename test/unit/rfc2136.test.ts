import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { TCPSocketListener } from "bun";
import type { DnsAnswer, Resolver } from "../../src/dns/resolver.ts";
import { DnsUpdater, type TsigKey } from "../../src/net/rfc2136.ts";

const SECRET = Uint8Array.fromBase64("c2VjcmV0LWtleS1mb3ItdGVzdHMtMzItYnl0ZXMhIQ==");
const KEY: TsigKey = { name: "bunzzle-key", algorithm: "hmac-sha256", secret: SECRET };

function nameAt(m: Uint8Array, at: number): { name: string; end: number } {
  const labels: string[] = [];
  let p = at;
  for (;;) {
    const len = m[p] as number;
    if (len === 0) return { name: labels.join("."), end: p + 1 };
    labels.push(new TextDecoder().decode(m.subarray(p + 1, p + 1 + len)));
    p += len + 1;
  }
}

function wireName(n: string): number[] {
  return [...n.split(".").flatMap((l) => [l.length, ...new TextEncoder().encode(l)]), 0];
}

const u16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const u48 = (n: number) => [
  ...u16(Math.floor(n / 2 ** 32)),
  ...u16((n >>> 16) & 0xffff),
  ...u16(n & 0xffff),
];

async function hmac(data: number[] | Uint8Array, key = SECRET) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, Uint8Array.from(data)));
}

const vars = (time: number, fudge: number) => [
  ...wireName("bunzzle-key"),
  ...u16(255),
  0,
  0,
  0,
  0,
  ...wireName("hmac-sha256"),
  ...u48(time),
  ...u16(fudge),
  ...u16(0),
  ...u16(0),
];

interface Seen {
  zone: string;
  updates: { name: string; type: number; cls: number; data: Uint8Array }[];
}

let server: TCPSocketListener<undefined>;
const seen: Seen[] = [];
let mode: "ok" | "badsig" | "notzone" | "unsigned" = "ok";

async function handle(req: Uint8Array): Promise<Uint8Array> {
  const v = new DataView(req.buffer, req.byteOffset, req.byteLength);
  const id = v.getUint16(0);
  let p = 12;
  const zone = nameAt(req, p);
  p = zone.end + 4;
  const updates: Seen["updates"] = [];
  for (let i = 0; i < v.getUint16(8); i++) {
    const n = nameAt(req, p);
    p = n.end;
    const type = v.getUint16(p);
    const cls = v.getUint16(p + 2);
    const len = v.getUint16(p + 8);
    updates.push({ name: n.name, type, cls, data: req.slice(p + 10, p + 10 + len) });
    p += 10 + len;
  }
  const tsigStart = p;
  const keyName = nameAt(req, p);
  p = keyName.end + 10;
  const alg = nameAt(req, p);
  p = alg.end;
  const time = v.getUint16(p) * 2 ** 32 + v.getUint32(p + 2);
  const fudge = v.getUint16(p + 6);
  const macLen = v.getUint16(p + 8);
  const mac = req.slice(p + 10, p + 10 + macLen);
  const body = req.slice(0, tsigStart);
  new DataView(body.buffer).setUint16(10, 0);
  const want = await hmac([...body, ...vars(time, fudge)]);
  const valid = keyName.name === "bunzzle-key" && want.every((x, i) => x === mac[i]);
  let rcode = 0;
  if (!valid || mode === "badsig") rcode = 9;
  else if (mode === "notzone") rcode = 10;
  else seen.push({ zone: zone.name, updates });
  const head = [
    ...u16(id),
    ...u16(0xa800 | rcode),
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    mode === "unsigned" ? 0 : 1,
  ];
  const question = [...wireName(zone.name), ...u16(6), ...u16(1)];
  const answer = [...head, ...question];
  if (mode === "unsigned") return Uint8Array.from(answer);
  const unsignedBody = [...answer.slice(0, 10), 0, 0, ...answer.slice(12)];
  const now = Math.floor(Date.now() / 1000);
  const badsig = !valid || mode === "badsig";
  const rmac = badsig
    ? new Uint8Array()
    : await hmac([...u16(mac.length), ...mac, ...unsignedBody, ...vars(now, 300)]);
  const rdata = [
    ...wireName("hmac-sha256"),
    ...u48(now),
    ...u16(300),
    ...u16(rmac.length),
    ...rmac,
    ...u16(id),
    ...u16(badsig ? 16 : 0),
    ...u16(0),
  ];
  return Uint8Array.from([
    ...answer,
    ...wireName("bunzzle-key"),
    ...u16(250),
    ...u16(255),
    0,
    0,
    0,
    0,
    ...u16(rdata.length),
    ...rdata,
  ]);
}

beforeAll(() => {
  server = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      async data(s, chunk) {
        const req = chunk.subarray(2);
        const res = await handle(new Uint8Array(req));
        s.write(Uint8Array.from([...u16(res.length), ...res]));
      },
    },
  });
});

afterAll(() => server.stop(true));

const resolver: Resolver = {
  async query(name, type): Promise<DnsAnswer> {
    const apex = name === "acme.test";
    return {
      name,
      type,
      rcode: 0,
      authenticated: false,
      ttl: 60,
      records: apex
        ? [
            {
              name,
              ttl: 60,
              rrtype: 6,
              rdata: new Uint8Array(),
              type: "SOA",
              soa: { mname: "ns.acme.test", serial: 1, minimum: 60 },
            },
          ]
        : [],
    };
  },
};

const updater = (key = KEY) =>
  new DnsUpdater({ host: "127.0.0.1", port: server.port }, key, resolver);

describe("RFC 2136 updates with TSIG", () => {
  test("finds the zone, replaces the record set and signs the request", async () => {
    mode = "ok";
    const r = await updater().upsert({
      type: "TXT",
      name: "s1._domainkey.acme.test",
      content: `v=DKIM1; k=rsa; p=${"A".repeat(400)}`,
    });
    expect(r).toEqual({ ok: true, action: "updated" });
    const last = seen.at(-1) as Seen;
    expect(last.zone).toBe("acme.test");
    expect(last.updates.map((u) => [u.name, u.type, u.cls])).toEqual([
      ["s1._domainkey.acme.test", 16, 255],
      ["s1._domainkey.acme.test", 16, 1],
    ]);
    const txt = last.updates[1]?.data as Uint8Array;
    expect(txt[0]).toBe(255);
    const mx = await updater().upsert({
      type: "MX",
      name: "bounce.acme.test",
      content: "in.bunzzle.test",
      priority: 10,
    });
    expect(mx.ok).toBe(true);
    const removed = await updater().remove({
      type: "TXT",
      name: "old._domainkey.acme.test",
      content: "v=DKIM1; p=x",
    });
    expect(removed).toEqual({ ok: true, action: "removed" });
    expect(seen.at(-1)?.updates[0]?.cls).toBe(254);
  });

  test("a wrong key, a refusal or an unsigned answer are reported, not trusted", async () => {
    mode = "ok";
    const wrong = await updater({ ...KEY, secret: new Uint8Array(32) }).upsert({
      type: "TXT",
      name: "x.acme.test",
      content: "v",
    });
    expect(wrong).toEqual({ ok: false, error: "DNS update refused: BADSIG" });
    mode = "notzone";
    expect(await updater().upsert({ type: "TXT", name: "x.acme.test", content: "v" })).toEqual({
      ok: false,
      error: "DNS update refused: NOTZONE",
    });
    mode = "unsigned";
    const unsigned = await updater().upsert({ type: "TXT", name: "x.acme.test", content: "v" });
    expect(unsigned).toEqual({ ok: false, error: "the DNS server did not sign its answer" });
    mode = "ok";
    expect(await updater().upsert({ type: "TXT", name: "x.other.test", content: "v" })).toEqual({
      ok: false,
      error: "no DNS zone found for x.other.test",
    });
  });
});
