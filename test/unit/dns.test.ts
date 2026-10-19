import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { manualClock } from "../../src/core/clock.ts";
import { cachingResolver } from "../../src/dns/cache.ts";
import { forbiddenReason, parseIPv6 } from "../../src/dns/ip.ts";
import { lookupDestination } from "../../src/dns/mx.ts";
import { createResolver, DnsError, parseServer, type Resolver } from "../../src/dns/resolver.ts";
import { decodeMessage, normalizeName } from "../../src/dns/wire.ts";
import { providerOf, siteOf } from "../../src/routing/providers.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";

let dns: FakeDns;
let resolver: Resolver;

beforeAll(async () => {
  dns = await startFakeDns({
    "example.test": {
      MX: [
        [10, "mx1.example.test"],
        [10, "mx2.example.test"],
        [20, "backup.example.test"],
      ],
    },
    "mx1.example.test": { A: ["203.0.114.1"], AAAA: ["2a00:1450::1"] },
    "mx2.example.test": { A: ["203.0.114.2"] },
    "backup.example.test": { A: ["203.0.114.3"] },
    "nullmx.test": { MX: [[0, ""]] },
    "nomx.test": { A: ["203.0.114.9"] },
    "servfail.test": { rcode: 2 },
    "private.test": { MX: [[10, "internal.private.test"]] },
    "internal.private.test": { A: ["10.0.0.5", "127.0.0.1"] },
    "alias.test": { CNAME: "example.test" },
    "big.test": { truncate: true, TXT: ["v=spf1 -all"] },
    "slow.test": { silent: true },
    "many.test": {
      MX: [1, 2, 3, 4, 5, 6, 7].map((i) => [i, `h${i}.many.test`] as [number, string]),
    },
    ...Object.fromEntries(
      [1, 2, 3, 4, 5, 6, 7].map((i) => [`h${i}.many.test`, { A: [`203.0.114.${10 + i}`] }]),
    ),
    "gmail.test": { MX: [[5, "gmail-smtp-in.l.google.com"]] },
  });
  resolver = createResolver({
    servers: [{ host: "127.0.0.1", port: dns.port }],
    timeoutMs: 200,
    attempts: 1,
  });
});

afterAll(() => dns.stop());

describe("wire format", () => {
  test("normalizes names and converts IDN to punycode", () => {
    expect(normalizeName("Example.COM.")).toBe("example.com");
    expect(normalizeName("bücher.de")).toBe("xn--bcher-kva.de");
    expect(() => normalizeName("bad..name")).toThrow();
    expect(() => normalizeName(`${"a".repeat(64)}.com`)).toThrow();
  });

  test("rejects compression loops and truncated packets", () => {
    const loop = new Uint8Array([0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1]);
    expect(() => decodeMessage(loop)).toThrow("compression loop");
    expect(() => decodeMessage(new Uint8Array([0, 1, 0x81]))).toThrow();
  });

  test("parses server specs", () => {
    expect(parseServer("1.1.1.1")).toEqual({ host: "1.1.1.1", port: 53 });
    expect(parseServer("127.0.0.1:5353")).toEqual({ host: "127.0.0.1", port: 5353 });
    expect(parseServer("[::1]:53")).toEqual({ host: "::1", port: 53 });
    expect(parseServer("2001:db8::1")).toEqual({ host: "2001:db8::1", port: 53 });
  });
});

describe("resolver", () => {
  test("tells NXDOMAIN and NODATA apart, with TTLs", async () => {
    const nx = await resolver.query("missing.test", "MX");
    expect(nx.rcode).toBe(3);
    const nodata = await resolver.query("nomx.test", "MX");
    expect(nodata.rcode).toBe(0);
    expect(nodata.records).toEqual([]);
    expect(nodata.ttl).toBe(30);
  });

  test("follows CNAME chains", async () => {
    const ans = await resolver.query("alias.test", "MX");
    expect(ans.records.map((r) => r.type === "MX" && r.mx.exchange).sort()).toEqual([
      "backup.example.test",
      "mx1.example.test",
      "mx2.example.test",
    ]);
  });

  test("falls back to TCP when the UDP answer is truncated", async () => {
    const ans = await resolver.query("big.test", "TXT");
    expect(ans.records).toEqual([
      { name: "big.test", ttl: 300, type: "TXT", strings: ["v=spf1 -all"] },
    ]);
    expect(dns.queries.filter((q) => q.name === "big.test").map((q) => q.tcp)).toEqual([
      false,
      true,
    ]);
  });

  test("times out with a DnsError", async () => {
    await expect(resolver.query("slow.test", "A")).rejects.toBeInstanceOf(DnsError);
  });

  test("reports the socket error when the server port is closed", async () => {
    const probe = await Bun.udpSocket({});
    const port = probe.port;
    probe.close();
    const closed = createResolver({
      servers: [{ host: "127.0.0.1", port }],
      timeoutMs: 200,
      attempts: 1,
    });
    const err = await closed.query("example.test", "A").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DnsError);
    expect((err as DnsError).message).toMatch(/ECONNREFUSED|no answer from/);
  });
});

describe("cache", () => {
  test("honors TTL, caps negatives and does not cache network errors", async () => {
    const clock = manualClock();
    let calls = 0;
    const counting: Resolver = {
      query(name, type) {
        calls++;
        return resolver.query(name, type);
      },
    };
    const cached = cachingResolver(counting, { clock });
    await cached.query("mx2.example.test", "A");
    await cached.query("MX2.example.test", "A");
    expect(calls).toBe(1);
    clock.advance(301_000);
    await cached.query("mx2.example.test", "A");
    expect(calls).toBe(2);
    await cached.query("servfail.test", "MX");
    clock.advance(6_000);
    await cached.query("servfail.test", "MX");
    expect(calls).toBe(4);
    await Promise.allSettled([cached.query("slow.test", "A"), cached.query("slow.test", "A")]);
    expect(calls).toBe(5);
    await cached.query("slow.test", "A").catch(() => {});
    expect(calls).toBe(6);
  });
});

describe("lookupDestination", () => {
  const lookup = (domain: string, extra: Partial<Parameters<typeof lookupDestination>[1]> = {}) =>
    lookupDestination(domain, { resolver, random: () => 0.5, ...extra });

  test("orders MX hosts by preference", async () => {
    const d = await lookup("example.test");
    if (d.kind !== "targets") throw new Error(d.reason);
    expect(d.targets.map((t) => t.host)).toEqual([
      "mx1.example.test",
      "mx2.example.test",
      "backup.example.test",
    ]);
  });

  test("shuffles hosts of equal preference", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const d = await lookupDestination("example.test", { resolver });
      if (d.kind === "targets") seen.add(d.targets[0]?.host ?? "");
    }
    expect([...seen].sort()).toEqual(["mx1.example.test", "mx2.example.test"]);
  });

  test("balances IPv4 and IPv6 when both are enabled", async () => {
    const d = await lookup("example.test", { families: [4, 6] });
    if (d.kind !== "targets") throw new Error(d.reason);
    expect(d.targets.slice(0, 2).map((t) => t.family)).toEqual([4, 6]);
  });

  test("caps the number of addresses at 5", async () => {
    const d = await lookup("many.test");
    if (d.kind !== "targets") throw new Error(d.reason);
    expect(d.targets).toHaveLength(5);
  });

  test("null MX fails immediately", async () => {
    expect(await lookup("nullmx.test")).toMatchObject({ kind: "fail", code: "5.1.10" });
  });

  test("NODATA uses the domain itself as implicit MX", async () => {
    const d = await lookup("nomx.test");
    expect(d).toMatchObject({ kind: "targets", implicit: true, mxHosts: ["nomx.test"] });
  });

  test("NXDOMAIN and SERVFAIL defer with different codes", async () => {
    expect(await lookup("missing.test")).toMatchObject({ kind: "defer", code: "nxdomain" });
    expect(await lookup("servfail.test")).toMatchObject({ kind: "defer", code: "dns-temporary" });
  });

  test("private and loopback destinations are refused unless allowed", async () => {
    const d = await lookup("private.test");
    expect(d).toMatchObject({ kind: "fail", code: "5.4.4" });
    expect(d.kind === "fail" && d.reason).toContain("forbidden network");
    const allowed = await lookup("private.test", { allowPrivate: true });
    expect(allowed.kind).toBe("targets");
  });

  test("our own addresses are always refused", async () => {
    const d = await lookup("private.test", {
      allowPrivate: true,
      ownAddresses: ["10.0.0.5", "127.0.0.1"],
    });
    expect(d.kind).toBe("fail");
  });
});

describe("ip safety", () => {
  test.each([
    ["127.0.0.1", "loopback"],
    ["10.1.2.3", "private"],
    ["172.31.0.1", "private"],
    ["192.168.1.1", "private"],
    ["169.254.169.254", "link-local"],
    ["100.64.0.1", "shared address space"],
    ["0.0.0.0", "this network"],
    ["224.0.0.1", "multicast"],
    ["::1", "loopback"],
    ["::", "unspecified"],
    ["fe80::1", "link-local"],
    ["fd00::1", "private"],
    ["::ffff:127.0.0.1", "loopback"],
    ["64:ff9b::a00:1", "private"],
  ])("%s is %s", (ip, reason) => {
    expect(forbiddenReason(ip)).toBe(reason);
  });

  test("public addresses pass", () => {
    expect(forbiddenReason("142.250.27.27")).toBeNull();
    expect(forbiddenReason("2a00:1450:4001::1b")).toBeNull();
    expect(forbiddenReason("172.32.0.1")).toBeNull();
  });

  test("parses IPv6 forms", () => {
    expect(parseIPv6("::")).toEqual(new Uint8Array(16));
    expect(parseIPv6("1:2:3:4:5:6:7:8")).not.toBeNull();
    expect(parseIPv6("1:2:3:4:5:6:7:8:9")).toBeNull();
    expect(parseIPv6("1::2::3")).toBeNull();
  });
});

describe("providers", () => {
  test("maps MX hosts to providers by suffix", () => {
    expect(providerOf("gmail-smtp-in.l.google.com")?.id).toBe("google");
    expect(providerOf("outlook-com.olc.protection.outlook.com.")?.id).toBe("microsoft");
    expect(providerOf("mx.notgoogle.com")).toBeNull();
    expect(siteOf(["B.example", "a.example", "b.example"])).toBe("a.example,b.example");
  });
});

describe("reverse DNS (D6)", () => {
  test("reverse names for IPv4 and IPv6", async () => {
    const { reverseName } = await import("../../src/dns/ip.ts");
    expect(reverseName("203.0.113.7")).toBe("7.113.0.203.in-addr.arpa");
    expect(reverseName("2001:db8::1")).toBe(
      "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
    );
  });

  test("forward-confirmed reverse DNS", async () => {
    const { checkReverse } = await import("../../src/dns/reverse.ts");
    const { startFakeDns } = await import("../support/fake-dns.ts");
    const { createResolver } = await import("../../src/dns/resolver.ts");
    const dns = await startFakeDns({
      "7.113.0.203.in-addr.arpa": { PTR: "mail.acme.test" },
      "mail.acme.test": { A: ["203.0.113.7"] },
      "8.113.0.203.in-addr.arpa": { PTR: "other.acme.test" },
      "other.acme.test": { A: ["203.0.113.99"] },
    });
    const resolver = createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] });
    expect(await checkReverse(resolver, "203.0.113.7")).toEqual({
      ip: "203.0.113.7",
      ptr: "mail.acme.test",
      forwardConfirmed: true,
      problem: null,
    });
    expect(await checkReverse(resolver, "203.0.113.8")).toMatchObject({
      forwardConfirmed: false,
      problem: "other.acme.test does not resolve back to 203.0.113.8",
    });
    expect((await checkReverse(resolver, "203.0.113.9")).problem).toBe(
      "no PTR record for 203.0.113.9",
    );
    dns.stop();
  });
});

describe("resolver failures", () => {
  test("a closed or unreachable server rejects with a DnsError and never crashes", async () => {
    const { createResolver, DnsError } = await import("../../src/dns/resolver.ts");
    const r = createResolver({
      servers: [{ host: "127.0.0.1", port: 9 }],
      timeoutMs: 300,
      attempts: 1,
    });
    await expect(r.query("example.test", "A")).rejects.toBeInstanceOf(DnsError);
  });
});
