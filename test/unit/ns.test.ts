import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createResolver } from "../../src/dns/resolver.ts";
import { decodeMessage, encodeQuery, Rcode, RRType } from "../../src/dns/wire.ts";
import { respond } from "../../src/ns/answer.ts";
import { DEFAULT_LIMITS, networkOf, ResponseLimiter } from "../../src/ns/limits.ts";
import { limitSummary, NsServer } from "../../src/ns/server.ts";
import { buildZone, type ZoneWire } from "../../src/ns/zone.ts";

const APEX = "dz.mail.test";
const NAMES = ["ns1.mail.test", "ns2.mail.test"];
const KEY = `v=DKIM1; k=rsa; p=${"A".repeat(520)}`;
const WIRE: ZoneWire = {
  serial: 7,
  records: [
    { name: `bza-r.k3j9.${APEX}`, type: "TXT", ttl: 300, value: KEY },
    { name: `k3j9.${APEX}`, type: "MX", ttl: 300, value: "mx.mail.test", priority: 10 },
    { name: `k3j9.${APEX}`, type: "TXT", ttl: 300, value: "v=spf1 ip4:192.0.2.1 -all" },
    { name: `_check.${APEX}`, type: "TXT", ttl: 300, value: "7" },
    { name: `_check.${APEX}`, type: "A", ttl: 300, value: "192.0.2.1" },
  ],
};
const zone = buildZone(APEX, NAMES, WIRE);

function query(name: string, type: number, opts: { edns?: boolean; id?: number } = {}) {
  const q = encodeQuery(opts.id ?? 1, name, type);
  if (opts.edns !== false) return q;
  const out = q.slice(0, q.length - 11);
  out[11] = 0;
  return out;
}

function ask(name: string, type: number, opts: { edns?: boolean; tcp?: boolean } = {}) {
  const r = respond(query(name, type, opts), APEX, zone, opts.tcp ?? false);
  if (!r) throw new Error("no reply");
  const flags = (r.bytes[2] as number) * 256 + (r.bytes[3] as number);
  return { reply: r, msg: decodeMessage(r.bytes), flags };
}

describe("ns answers", () => {
  test("answers TXT with AA set, RA clear, split into 255-byte strings", () => {
    const { msg, flags } = ask(`bza-r.k3j9.${APEX}`, RRType.TXT);
    expect(msg.rcode).toBe(Rcode.NOERROR);
    expect(flags & 0x0400).toBe(0x0400);
    expect(flags & 0x0080).toBe(0);
    const txt = msg.answers[0];
    expect(txt?.type === "TXT" && txt.strings.map((s) => s.length)).toEqual([255, 255, 28]);
    expect(txt?.type === "TXT" && txt.strings.join("")).toBe(KEY);
  });

  test("keeps the question case and matches names case-insensitively", () => {
    const r = respond(query(`K3J9.Dz.Mail.Test`, RRType.MX), APEX, zone, false);
    const bytes = r?.bytes as Uint8Array;
    expect(new TextDecoder().decode(bytes.subarray(13, 17))).toBe("K3J9");
    const msg = decodeMessage(bytes);
    expect(msg.answers[0]?.type === "MX" && msg.answers[0].mx).toEqual({
      preference: 10,
      exchange: "mx.mail.test",
    });
  });

  test("NXDOMAIN and NODATA carry the SOA, empty non-terminals are NODATA", () => {
    const nx = ask(`nope.${APEX}`, RRType.TXT);
    expect(nx.msg.rcode).toBe(Rcode.NXDOMAIN);
    expect(nx.msg.authority[0]?.type === "SOA" && nx.msg.authority[0].soa.minimum).toBe(300);
    expect(nx.msg.authority[0]?.name).toBe(APEX);
    expect(nx.reply.kind).toBe("negative");
    const nodata = ask(`k3j9.${APEX}`, RRType.AAAA);
    expect(nodata.msg.rcode).toBe(Rcode.NOERROR);
    expect(nodata.msg.answers).toEqual([]);
    expect(nodata.msg.authority[0]?.type).toBe("SOA");
    expect(ask(`bza-r.k3j9.${APEX}`, RRType.A).msg.rcode).toBe(Rcode.NOERROR);
    expect(ask(`x.bza-r.k3j9.${APEX}`, RRType.A).msg.rcode).toBe(Rcode.NXDOMAIN);
  });

  test("apex has SOA and NS", () => {
    const soa = ask(APEX, RRType.SOA).msg.answers[0];
    expect(soa?.type === "SOA" && soa.soa.mname).toBe("ns1.mail.test");
    const ns = ask(APEX, RRType.NS).msg.answers.map((a) => a.type === "NS" && a.target);
    expect(ns).toEqual(NAMES);
  });

  test("refuses names outside the zone, zone transfers and other classes", () => {
    expect(ask("example.com", RRType.A).msg.rcode).toBe(Rcode.REFUSED);
    expect(ask("dz.mail.test.evil", RRType.A).msg.rcode).toBe(Rcode.REFUSED);
    expect(ask(APEX, 252, { tcp: true }).msg.rcode).toBe(Rcode.REFUSED);
    expect(ask(APEX, 251).msg.rcode).toBe(Rcode.REFUSED);
    const chaos = query(APEX, RRType.TXT);
    chaos[12 + APEX.length + 2 + 3] = 3;
    expect(decodeMessage(respond(chaos, APEX, zone, false)?.bytes as Uint8Array).rcode).toBe(
      Rcode.REFUSED,
    );
  });

  test("never recurses: RD is echoed, RA stays clear", () => {
    const { flags } = ask("example.com", RRType.A);
    expect(flags & 0x0100).toBe(0x0100);
    expect(flags & 0x0080).toBe(0);
  });

  test("ANY gets one HINFO", () => {
    const { msg } = ask(`k3j9.${APEX}`, 255);
    expect(msg.answers.map((a) => a.rrtype)).toEqual([13]);
  });

  test("NOTIFY and UPDATE are refused, other opcodes NOTIMP", () => {
    for (const [opcode, rcode] of [
      [4, Rcode.REFUSED],
      [5, Rcode.REFUSED],
      [2, Rcode.NOTIMP],
    ] as const) {
      const q = query(APEX, RRType.SOA);
      q[2] = ((q[2] as number) & 0x87) | (opcode << 3);
      const r = respond(q, APEX, zone, false) as { bytes: Uint8Array };
      expect((r.bytes[3] as number) & 0xf).toBe(rcode);
    }
  });

  test("drops responses and malformed queries on UDP, FORMERR on TCP", () => {
    const resp = query(APEX, RRType.SOA);
    resp[2] = (resp[2] as number) | 0x80;
    expect(respond(resp, APEX, zone, false)).toBeNull();
    const trailing = new Uint8Array([...query(APEX, RRType.SOA), 0]);
    expect(respond(trailing, APEX, zone, false)).toBeNull();
    expect(((respond(trailing, APEX, zone, true)?.bytes[3] as number) & 0xf) as number).toBe(
      Rcode.FORMERR,
    );
    const pointer = query(APEX, RRType.SOA);
    pointer[12] = 0xc0;
    expect(respond(pointer, APEX, zone, false)).toBeNull();
    expect(respond(new Uint8Array(5), APEX, zone, true)).toBeNull();
  });

  test("answers BADVERS for EDNS versions above 0", () => {
    const q = query(APEX, RRType.SOA);
    q[q.length - 5] = 1;
    const r = respond(q, APEX, zone, false) as { bytes: Uint8Array };
    expect((r.bytes[3] as number) & 0xf).toBe(0);
    expect(r.bytes[r.bytes.length - 6]).toBe(1);
  });

  test("truncates over 512 bytes without EDNS, never over TCP", () => {
    const name = `bza-r.k3j9.${APEX}`;
    const udp = ask(name, RRType.TXT, { edns: false });
    expect(udp.msg.truncated).toBe(true);
    expect(udp.msg.answers).toEqual([]);
    expect(udp.reply.bytes.length).toBeLessThan(100);
    expect(ask(name, RRType.TXT, { edns: false, tcp: true }).msg.truncated).toBe(false);
  });

  test("SERVFAIL inside the zone before any zone is loaded", () => {
    const r = respond(query(`k3j9.${APEX}`, RRType.MX), APEX, null, false);
    expect(decodeMessage(r?.bytes as Uint8Array).rcode).toBe(Rcode.SERVFAIL);
    const out = respond(query("example.com", RRType.MX), APEX, null, false);
    expect(decodeMessage(out?.bytes as Uint8Array).rcode).toBe(Rcode.REFUSED);
  });
});

describe("zone build", () => {
  test("rejects names outside the zone and record sets too big for UDP", () => {
    const outside = {
      serial: 1,
      records: [{ name: "x.test", type: "A", ttl: 1, value: "192.0.2.1" }],
    };
    expect(() => buildZone(APEX, NAMES, outside as ZoneWire)).toThrow(/outside the zone/);
    const big = {
      serial: 1,
      records: [1, 2, 3].map(() => ({ name: `a.${APEX}`, type: "TXT", ttl: 1, value: KEY })),
    };
    expect(() => buildZone(APEX, NAMES, big as ZoneWire)).toThrow(/more than 1232/);
  });
});

describe("response rate limit", () => {
  test("groups clients by /24 and /56", () => {
    expect(networkOf("192.0.2.9", 24, 56)).toBe(networkOf("192.0.2.200", 24, 56));
    expect(networkOf("192.0.2.9", 24, 56)).not.toBe(networkOf("192.0.3.9", 24, 56));
    expect(networkOf("::ffff:192.0.2.9", 24, 56)).toBe(networkOf("192.0.2.1", 24, 56));
    expect(networkOf("2001:db8:0:ff00::1", 24, 56)).toBe(networkOf("2001:db8:0:ff42::2", 24, 56));
    expect(networkOf("2001:db8:0:100::1", 24, 56)).not.toBe(networkOf("2001:db8::1", 24, 56));
  });

  test("burst, then drop by default, refill over time, kinds apart", () => {
    let t = 0;
    const lim = new ResponseLimiter(DEFAULT_LIMITS, () => t);
    const seen = Array.from({ length: 44 }, () => lim.check("192.0.2.1", "answer"));
    expect(seen.slice(0, 40).every((v) => v === "send")).toBe(true);
    expect(seen.slice(40)).toEqual(["drop", "drop", "drop", "drop"]);
    expect(lim.check("192.0.2.77", "negative")).toBe("send");
    t += 100;
    expect(lim.check("192.0.2.5", "answer")).toBe("send");
    expect(lim.check("192.0.2.5", "answer")).toBe("send");
    expect(lim.check("192.0.2.5", "answer")).toBe("drop");
  });

  test("with slip 2 every second limited answer is a truncated reply", () => {
    const lim = new ResponseLimiter({ ...DEFAULT_LIMITS, slip: 2 }, () => 0);
    const seen = Array.from({ length: 44 }, () => lim.check("192.0.2.1", "answer"));
    expect(seen.slice(40)).toEqual(["slip", "drop", "slip", "drop"]);
  });

  test("global cap and bounded table", () => {
    const lim = new ResponseLimiter({ ...DEFAULT_LIMITS, globalPerSec: 3, maxEntries: 2 }, () => 0);
    const out = ["10.0.0.1", "10.0.1.1", "10.0.2.1", "10.0.3.1"].map((ip) =>
      lim.check(ip, "answer"),
    );
    expect(out).toEqual(["send", "send", "send", "global"]);
    expect(lim.size).toBe(2);
  });
});

describe("limit summary", () => {
  test("is empty without limit hits and counts only the last interval", () => {
    const server = new NsServer({ apex: APEX, names: NAMES });
    server.load(WIRE);
    const a = server.snapshot();
    server.answerUdp(query(`nope.${APEX}`, RRType.A), "192.0.2.1");
    const b = server.snapshot();
    expect(limitSummary(a, b)).toBeNull();
    for (let i = 0; i < 45; i++) server.answerUdp(query(`k3j9.${APEX}`, RRType.MX), "192.0.2.1");
    const c = server.snapshot();
    expect(limitSummary(b, c)).toMatchObject({ limited: 5, slipped: 0 });
    expect(limitSummary(c, server.snapshot())).toBeNull();
  });
});

test("listening on any port tries another port when the TCP one is taken", async () => {
  const server = new NsServer({ apex: APEX, names: NAMES });
  const real = Bun.listen;
  let calls = 0;
  Bun.listen = ((opts: Parameters<typeof Bun.listen>[0]) => {
    calls++;
    if (calls === 1) throw Object.assign(new Error("Failed to listen"), { code: "EADDRINUSE" });
    return real(opts);
  }) as typeof Bun.listen;
  try {
    const port = await server.listen("127.0.0.1", 0);
    expect(calls).toBe(2);
    expect(port).toBeGreaterThan(0);
  } finally {
    Bun.listen = real;
    server.stop();
  }
  const fixed = new NsServer({ apex: APEX, names: NAMES });
  const blocker = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  try {
    await expect(fixed.listen("127.0.0.1", blocker.port)).rejects.toThrow();
  } finally {
    blocker.stop(true);
    fixed.stop();
  }
});

describe("ns server on sockets", () => {
  let server: NsServer;
  let port: number;

  beforeAll(async () => {
    server = new NsServer({
      apex: APEX,
      names: NAMES,
      tcp: {
        perIp: 2,
        total: 10,
        idleSec: 10,
        readMs: 200,
        queriesPerConnection: 3,
        maxQuery: 4096,
      },
    });
    server.load(WIRE);
    port = await server.listen("127.0.0.1", 0);
  });

  afterAll(() => server.stop());

  test("a resolver gets answers over UDP and TCP", async () => {
    const r = createResolver({ servers: [{ host: "127.0.0.1", port }], timeoutMs: 1000 });
    const txt = await r.query(`bza-r.k3j9.${APEX}`, "TXT");
    expect(txt.records[0]?.type === "TXT" && txt.records[0].strings.join("")).toBe(KEY);
    const tcp = await tcpAsk(port, query(`k3j9.${APEX}`, RRType.MX));
    expect(tcp[0]?.answers[0]?.type).toBe("MX");
    expect(server.snapshot().serial).toBe(7);
  });

  test("TCP closes after the per-connection query limit and refuses extra connections", async () => {
    const q = query(`_check.${APEX}`, RRType.A);
    const answers = await tcpAsk(port, q, 5);
    expect(answers.length).toBe(3);
    const before = server.snapshot().tcp.refused;
    const held = await Promise.all([openTcp(port), openTcp(port), openTcp(port)]);
    await Bun.sleep(50);
    expect(server.snapshot().tcp.refused).toBe(before + 1);
    for (const s of held) s.end();
  });

  test("a half-sent TCP query is closed after the read timeout", async () => {
    const before = server.snapshot().tcp.timeouts;
    const s = await openTcp(port);
    s.write(new Uint8Array([0, 40, 1, 2]));
    await Bun.sleep(400);
    expect(server.snapshot().tcp.timeouts).toBe(before + 1);
    s.end();
  });
});

function openTcp(port: number) {
  return Bun.connect({ hostname: "127.0.0.1", port, socket: { data() {} } });
}

async function tcpAsk(port: number, q: Uint8Array, times = 1) {
  const framed = new Uint8Array(q.length + 2);
  framed[1] = q.length;
  framed.set(q, 2);
  const out: ReturnType<typeof decodeMessage>[] = [];
  let buf = new Uint8Array(0);
  const { promise, resolve } = Promise.withResolvers<void>();
  const s = await Bun.connect({
    hostname: "127.0.0.1",
    port,
    socket: {
      data(_s, chunk) {
        const next = new Uint8Array(buf.length + chunk.length);
        next.set(buf);
        next.set(chunk, buf.length);
        buf = next;
        while (
          buf.length >= 2 &&
          buf.length >= ((buf[0] as number) << 8) + (buf[1] as number) + 2
        ) {
          const len = ((buf[0] as number) << 8) + (buf[1] as number);
          out.push(decodeMessage(buf.subarray(2, len + 2)));
          buf = buf.slice(len + 2);
        }
        if (out.length === times) resolve();
      },
      close: () => resolve(),
    },
  });
  for (let i = 0; i < times; i++) s.write(framed);
  await Promise.race([promise, Bun.sleep(1000)]);
  s.end();
  return out;
}
