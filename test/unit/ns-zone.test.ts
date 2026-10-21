import { describe, expect, test } from "bun:test";
import type { Logger } from "../../src/core/log.ts";
import { type DelegatedDomain, zoneLabel, zoneRecords } from "../../src/domains/delegated.ts";
import { NsServer } from "../../src/ns/server.ts";
import { zonePublisher } from "../../src/roles/core-zone.ts";

const ZONE = "dz.mail.example.net";
const RSA = { selector: "x", algorithm: "rsa-sha256" as const, publicKey: "M".repeat(392) };
const ED = { selector: "y", algorithm: "ed25519-sha256" as const, publicKey: "E".repeat(44) };
const DOMAINS: DelegatedDomain[] = [
  { name: "shop.example", keys: { "bza-r": RSA, "bza-e": ED, "bzb-r": RSA } },
  { name: "app.example", keys: {} },
];

function quietLog() {
  const lines: { level: string; msg: string }[] = [];
  const at = (level: string) => (msg: string) => lines.push({ level, msg });
  const log = { debug: at("debug"), info: at("info"), warn: at("warn"), error: at("error") };
  return { log: log as unknown as Logger, lines };
}

describe("zone labels", () => {
  test("16 base32 characters, stable and case-insensitive", () => {
    const l = zoneLabel("Shop.Example");
    expect(l).toMatch(/^[a-z2-7]{16}$/);
    expect(zoneLabel("shop.example")).toBe(l);
    expect(zoneLabel("shop.example.co")).not.toBe(l);
  });
});

describe("zone records", () => {
  test("return path MX and SPF per domain, DKIM per filled slot, shared _spf", () => {
    const records = zoneRecords({
      zone: ZONE,
      ttl: 300,
      sourceIps: ["192.0.2.10", "2001:db8::10"],
      inboundHost: "mx.mail.example.net",
      domains: DOMAINS,
    });
    const shop = `${zoneLabel("shop.example")}.${ZONE}`;
    const app = `${zoneLabel("app.example")}.${ZONE}`;
    const spf = "v=spf1 ip4:192.0.2.10 ip6:2001:db8::10 ~all";
    expect(records.find((r) => r.name === `_spf.${ZONE}`)?.value).toBe(spf);
    expect(records.filter((r) => r.name === shop)).toEqual([
      { name: shop, type: "MX", ttl: 300, value: "mx.mail.example.net", priority: 10 },
      { name: shop, type: "TXT", ttl: 300, value: spf },
    ]);
    expect(records.filter((r) => r.name.endsWith(`.${shop}`)).map((r) => r.name)).toEqual([
      `bza-r.${shop}`,
      `bzb-r.${shop}`,
      `bza-e.${shop}`,
    ]);
    expect(records.find((r) => r.name === `bza-e.${shop}`)?.value).toBe(
      `v=DKIM1; k=ed25519; p=${"E".repeat(44)}`,
    );
    expect(records.filter((r) => r.name === app).length).toBe(2);
  });

  test("no SPF without source IPs, no MX without an inbound host", () => {
    const records = zoneRecords({
      zone: ZONE,
      ttl: 300,
      sourceIps: [],
      inboundHost: null,
      domains: DOMAINS,
    });
    expect(records.some((r) => r.value.startsWith("v=spf1") || r.type === "MX")).toBe(false);
  });
});

describe("zone publisher", () => {
  function setup(domains: DelegatedDomain[]) {
    const server = new NsServer({ apex: ZONE, names: ["ns1.mail.example.net"] });
    const calls: string[] = [];
    let down = false;
    const ns = {
      call: async (method: string, params: unknown) => {
        calls.push(method);
        if (down) throw new Error("ns is down");
        if (method === "stats") return server.snapshot() as never;
        server.load(params as never);
        return { serial: server.serial } as never;
      },
    };
    let t = 1_700_000_000_000;
    const quiet = quietLog();
    const pub = zonePublisher({
      ns: ns as never,
      zone: ZONE,
      ttl: 300,
      sourceIps: ["192.0.2.10"],
      inboundHost: "mx.mail.example.net",
      domains: () => domains,
      log: quiet.log,
      now: () => t,
    });
    return {
      server,
      calls,
      pub,
      lines: quiet.lines,
      setDown: (v: boolean) => {
        down = v;
      },
      advance: (ms: number) => {
        t += ms;
      },
    };
  }

  test("pushes once, then only after a change, with a growing serial", async () => {
    const domains = [...DOMAINS];
    const s = setup(domains);
    expect(await s.pub.tick()).toBe(1_700_000_000);
    expect(s.calls).toEqual(["stats", "zone"]);
    expect(await s.pub.tick()).toBe(1_700_000_000);
    expect(s.calls).toEqual(["stats", "zone", "stats"]);
    domains.push({ name: "new.example", keys: { "bza-r": RSA } });
    expect(await s.pub.tick()).toBe(1_700_000_001);
    s.advance(60_000);
    domains.pop();
    expect(await s.pub.tick()).toBe(1_700_000_060);
  });

  test("the zone with full slots fits the ns limits", async () => {
    const s = setup(DOMAINS);
    const serial = await s.pub.tick();
    expect(serial).not.toBeNull();
    expect(s.server.snapshot().names).toBeGreaterThan(5);
  });

  test("pushes again when ns comes back without the zone", async () => {
    const s = setup(DOMAINS);
    await s.pub.tick();
    s.setDown(true);
    expect(await s.pub.tick()).toBeNull();
    expect(await s.pub.tick()).toBeNull();
    expect(s.lines.filter((l) => l.level === "warn").length).toBe(1);
    s.setDown(false);
    const fresh = new NsServer({ apex: ZONE, names: ["ns1.mail.example.net"] });
    Object.assign(s.server, { snapshot: () => fresh.snapshot() });
    expect(await s.pub.tick()).toBe(1_700_000_001);
    expect(s.lines.at(-1)?.msg).toBe("zone pushed to ns again");
  });
});
