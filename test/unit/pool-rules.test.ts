import { expect, test } from "bun:test";
import {
  choosePool,
  createPoolRule,
  deletePoolRule,
  listPoolRules,
} from "../../src/accounts/pool-rules.ts";
import { ownPool } from "../../src/accounts/pools.ts";
import { DEFAULT_PROJECT, type ProjectId } from "../../src/accounts/projects.ts";
import { openDatabase } from "../../src/core/store/db.ts";

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
