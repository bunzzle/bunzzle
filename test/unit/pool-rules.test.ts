import { describe, expect, test } from "bun:test";
import {
  choosePool,
  createPoolRule,
  deletePoolRule,
  listPoolRules,
} from "../../src/accounts/pool-rules.ts";
import { ownPool } from "../../src/accounts/pools.ts";
import { DEFAULT_PROJECT, type ProjectId } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import { claim } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import type { DeliveryTransport } from "../../src/delivery/transport.ts";
import { providerOfTargets } from "../../src/routing/providers.ts";
import { Shaper } from "../../src/shaping/shaper.ts";
import { memoryBodies } from "../support/bodies.ts";

const T0 = Date.UTC(2026, 9, 22);
const SHOP = "shop" as ProjectId;
const POOLS = new Set(["main", "bulk", "warm", "ms", "shop-own", "gone-ips"]);
POOLS.delete("gone-ips");

function setup() {
  const db = openDatabase({ path: ":memory:" });
  db.run("INSERT INTO projects (id, name, created_at) VALUES ('shop', 'shop', 0)");
  ownPool(db, "shop-own", SHOP, T0);
  const choose = (
    project: ProjectId,
    domain: string,
    provider: string | null,
    senderPool: string | null = null,
  ) => choosePool(db, { project, domain, provider, senderPool }, (p) => POOLS.has(p));
  return { db, choose };
}

test("precedence: project rule, then sender pool, then server rule, then the lane pool", () => {
  const { db, choose } = setup();
  expect(choose(SHOP, "example.com", "google")).toEqual({ pool: null, rule: null, skipped: [] });
  const server = createPoolRule(db, null, "google", "warm", T0);
  expect(choose(SHOP, "example.com", "google")).toEqual({
    pool: "warm",
    rule: server?.id ?? null,
    skipped: [],
  });
  expect(choose(SHOP, "example.com", "google", "main")).toMatchObject({ pool: "main", rule: null });
  const own = createPoolRule(db, SHOP, "google", "shop-own", T0);
  expect(choose(SHOP, "example.com", "google", "main")).toMatchObject({
    pool: "shop-own",
    rule: own?.id,
  });
  expect(choose(DEFAULT_PROJECT, "example.com", "google")).toMatchObject({ pool: "warm" });
});

test("an exact domain wins over its provider inside one level", () => {
  const { db, choose } = setup();
  createPoolRule(db, null, "microsoft", "ms", T0);
  const exact = createPoolRule(db, null, "contoso.example", "warm", T0);
  expect(choose(SHOP, "contoso.example", "microsoft")).toMatchObject({
    pool: "warm",
    rule: exact?.id,
  });
  expect(choose(SHOP, "other.example", "microsoft")).toMatchObject({ pool: "ms" });
});

test("a rule that cannot be used is skipped and the next one applies", () => {
  const { db, choose } = setup();
  const dead = createPoolRule(db, SHOP, "example.com", "gone-ips", T0);
  const provider = createPoolRule(db, SHOP, "google", "shop-own", T0);
  expect(choose(SHOP, "example.com", "google")).toEqual({
    pool: "shop-own",
    rule: provider?.id ?? null,
    skipped: [dead?.id as string],
  });
  const foreign = createPoolRule(db, null, "yahoo", "shop-own", T0);
  expect(choose(DEFAULT_PROJECT, "y.example", "yahoo")).toEqual({
    pool: null,
    rule: null,
    skipped: [foreign?.id as string],
  });
  expect(choose(SHOP, "y.example", "yahoo")).toMatchObject({ pool: "shop-own" });
});

test("relay is a server target; project rules are kept apart", () => {
  const { db, choose } = setup();
  const relay = createPoolRule(db, null, "apple", "relay", T0);
  expect(choose(SHOP, "icloud.com", "apple")).toEqual({
    relay: true,
    rule: relay?.id as string,
    skipped: [],
  });
  expect(choose(SHOP, "icloud.com", "apple", "main")).toMatchObject({ pool: "main" });
  expect(createPoolRule(db, null, "apple", "warm", T0)).toBeNull();
  const own = createPoolRule(db, SHOP, "apple", "shop-own", T0);
  expect(listPoolRules(db, SHOP).map((r) => r.id)).toEqual([own?.id as string]);
  expect(listPoolRules(db, null).map((r) => r.id)).toEqual([relay?.id as string]);
  expect(deletePoolRule(db, DEFAULT_PROJECT, own?.id ?? "")).toBe(false);
  expect(deletePoolRule(db, SHOP, own?.id ?? "")).toBe(true);
});

describe("the delivery handler sends where the rules say", () => {
  async function harness(
    rules: [project: ProjectId | null, match: string, pool: string][],
    relay: boolean,
  ) {
    const clock = manualClock();
    const db = openDatabase({ path: ":memory:" });
    const log = createLogger("error", {}, () => {});
    for (const [project, match, pool] of rules) createPoolRule(db, project, match, pool, 0);
    let sent = null as { source: string; via?: string } | null;
    let mx = "aspmx.l.google.com";
    const transport: DeliveryTransport = {
      lookup: async (domain) => ({
        kind: "targets",
        domain,
        mxHosts: [mx],
        implicit: false,
        authenticated: false,
        targets: [{ host: mx, preference: 10, address: "192.0.2.1", family: 4 }],
        skipped: [],
      }),
      deliver: async (req) => {
        sent = { source: req.source ?? "", ...(req.via ? { via: req.via } : {}) };
        throw new Error("sent");
      },
    };
    const ips = [
      { ip: "203.0.113.1", pool: "main", established: true },
      { ip: "203.0.113.2", pool: "warm", established: true },
    ];
    const handle = deliveryHandler({
      bodies: memoryBodies(),
      db,
      log,
      transport,
      clock,
      shaper: new Shaper({ log, clock }),
      ips,
      relayRoutes: () => (relay ? { targets: [], blocked: false } : null),
      poolRules: (job) => choosePool(db, job, (p) => ips.some((x) => x.pool === p)),
    });
    let n = 0;
    const send = async (o: { mx?: string; senderPool?: string } = {}) => {
      if (o.mx) mx = o.mx;
      const id = `m${n++}`;
      enqueueEmail(
        db,
        DEFAULT_PROJECT,
        {
          id,
          body: { epoch: 1, size: 1 },
          from: "a@bunzzle.test",
          recipients: ["x@company.example"],
          smtpUtf8: false,
          requireTls: false,
          ...(o.senderPool ? { metadata: { pool: o.senderPool } } : {}),
        },
        clock.now(),
      );
      const [job] = claim(db, clock.now(), 1, 60_000);
      sent = null;
      await expect(handle(job as NonNullable<typeof job>)).rejects.toThrow("sent");
      return sent as { source: string; via?: string } | null;
    };
    return { send };
  }

  const attempt = async (
    rules: [project: ProjectId | null, match: string, pool: string][],
    relay: boolean,
  ) => (await harness(rules, relay)).send();

  test("no rule: the lane pool", async () => {
    expect(await attempt([], true)).toEqual({ source: "203.0.113.1" });
  });

  test("a provider rule moves a company domain on that provider's MX to another pool", async () => {
    expect(await attempt([[null, "google", "warm"]], true)).toEqual({ source: "203.0.113.2" });
  });

  test("an unknown provider: provider rules do not apply, the normal order does", async () => {
    const h = await harness(
      [
        [null, "google", "warm"],
        [DEFAULT_PROJECT, "google", "warm"],
      ],
      true,
    );
    const filter = "mx.filter.example";
    expect(await h.send({ mx: filter })).toEqual({ source: "203.0.113.1" });
    expect(await h.send({ mx: filter, senderPool: "warm" })).toEqual({ source: "203.0.113.2" });
    const exact = await harness([[null, "company.example", "warm"]], true);
    expect(await exact.send({ mx: filter })).toEqual({ source: "203.0.113.2" });
  });

  test("each attempt follows the MX answer it gets, so an MX change moves the next attempt", async () => {
    const h = await harness([[null, "google", "warm"]], true);
    expect(await h.send({ mx: "aspmx.l.google.com" })).toEqual({ source: "203.0.113.2" });
    expect(await h.send({ mx: "company-com.mail.protection.outlook.com" })).toEqual({
      source: "203.0.113.1",
    });
    expect(await h.send({ mx: "alt2.aspmx.l.google.com" })).toEqual({ source: "203.0.113.2" });
  });

  test("a relay rule sends through the relay, and is ignored without one", async () => {
    expect(await attempt([[null, "company.example", "relay"]], true)).toMatchObject({
      via: "relay",
    });
    expect(await attempt([[null, "company.example", "relay"]], false)).toEqual({
      source: "203.0.113.1",
    });
  });
});

test("the provider is the one shared by the most preferred MX hosts, whatever their order", () => {
  const t = (host: string, preference: number) => ({ host, preference });
  const id = (targets: { host: string; preference: number }[]) =>
    providerOfTargets(targets)?.id ?? null;
  expect(id([t("aspmx.l.google.com", 1), t("alt1.aspmx.l.google.com", 5)])).toBe("google");
  expect(id([t("mx.company.example", 20), t("company-com.mail.protection.outlook.com", 10)])).toBe(
    "microsoft",
  );
  const mixed = [t("aspmx.l.google.com", 10), t("company-com.mail.protection.outlook.com", 10)];
  expect(id(mixed)).toBeNull();
  expect(id([...mixed].reverse())).toBeNull();
  expect(id([t("mx.filter.example", 10), t("aspmx.l.google.com", 20)])).toBeNull();
  expect(id([t("gmail.com", 0)])).toBeNull();
  expect(id([])).toBeNull();
});
