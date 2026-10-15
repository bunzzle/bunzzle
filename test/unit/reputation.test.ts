import { describe, expect, test } from "bun:test";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import {
  activeHold,
  anomalyThreshold,
  countKeyBulk,
  countSender,
  reputationGuard,
} from "../../src/guards/guards.ts";
import {
  choose,
  countWarmup,
  DAY_MS,
  estimatedDays,
  getWarmup,
  health,
  rollover,
} from "../../src/ips/warmup.ts";

const T0 = 20_000 * DAY_MS + 3_600_000;
const lines: string[] = [];
const log = createLogger("info", {}, (l) => lines.push(l));
const IPS = [
  { ip: "203.0.113.7", pool: "main", established: false },
  { ip: "203.0.113.8", pool: "main", established: false },
  { ip: "203.0.113.9", pool: "bulk", established: true },
];
const none = () => null;

describe("warm-up (H5)", () => {
  test("health from yesterday's numbers", () => {
    const c = { sent: 100, delivered: 98, deferred: 2, bounced: 0, blocked: 0, complained: 0 };
    expect(health(c, 100)).toBe("healthy");
    expect(health({ ...c, sent: 20, delivered: 20, deferred: 0 }, 100)).toBe("quiet");
    expect(health({ ...c, deferred: 15 }, 100)).toBe("borderline");
    expect(health({ ...c, bounced: 12 }, 100)).toBe("bad");
    expect(health({ ...c, blocked: 1 }, 100)).toBe("bad");
    expect(health({ ...c, complained: 1, delivered: 200 }, 100)).toBe("bad");
  });

  test("a healthy IP doubles its budget each day in week one, then grows by half", () => {
    const db = openDatabase({ path: ":memory:" });
    let now = T0;
    const budgets: number[] = [];
    for (let day = 0; day < 9; day++) {
      const w = getWarmup(db, "203.0.113.7", "google");
      const budget = w?.budget ?? 50;
      budgets.push(budget);
      countWarmup(db, "203.0.113.7", "google", { sent: budget, delivered: budget }, now);
      now += DAY_MS;
      rollover(db, now, log);
    }
    expect(budgets).toEqual([50, 100, 200, 400, 800, 1600, 3200, 6400, 9600]);
    expect(estimatedDays(9600, 9)).toBe(14);
  });

  test("trouble steps back and alerts; a quiet day holds", () => {
    const db = openDatabase({ path: ":memory:" });
    countWarmup(db, "203.0.113.7", "google", { sent: 50, delivered: 50 }, T0);
    rollover(db, T0 + DAY_MS, log);
    countWarmup(db, "203.0.113.7", "google", { sent: 100, delivered: 90, blocked: 1 }, T0 + DAY_MS);
    rollover(db, T0 + 2 * DAY_MS, log);
    expect(getWarmup(db, "203.0.113.7", "google")?.budget).toBe(50);
    expect(lines.some((l) => l.includes("warm-up stepped back"))).toBe(true);
    countWarmup(db, "203.0.113.7", "google", { sent: 5, delivered: 5 }, T0 + 2 * DAY_MS);
    rollover(db, T0 + 3 * DAY_MS, log);
    expect(getWarmup(db, "203.0.113.7", "google")?.budget).toBe(50);
  });

  test("choice is stable per destination, skips paused and over-budget IPs, waits for tomorrow", () => {
    const db = openDatabase({ path: ":memory:" });
    const pick = (target: string, n = 1, paused: (ip: string) => number | null = none) =>
      choose(db, IPS, "transactional", target, "google", n, T0, paused);
    const first = pick("google");
    expect(pick("google")).toEqual(first);
    expect("source" in first).toBe(true);
    const chosen = (first as { source: string }).source;
    const other = IPS.find((x) => x.pool === "main" && x.ip !== chosen)?.ip as string;
    expect(pick("google", 1, (ip) => (ip === chosen ? T0 + 60_000 : null))).toEqual({
      source: other,
    });
    countWarmup(db, chosen, "google", { sent: 50 }, T0);
    expect(pick("google")).toEqual({ source: other });
    countWarmup(db, other, "google", { sent: 49 }, T0);
    const wait = pick("google", 2);
    expect("wait" in wait && wait.wait.reason).toContain("budget");
    expect("wait" in wait && wait.wait.delayMs).toBeGreaterThan(DAY_MS - 3_600_000);
  });

  test("bulk uses the bulk pool; established IPs are never capped", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(choose(db, IPS, "bulk", "google", "google", 10_000, T0, none)).toEqual({
      source: "203.0.113.9",
    });
    expect(choose(db, [], "bulk", "google", "google", 1, T0, none)).toEqual({ source: "default" });
  });
});

describe("guards (I8, J4)", () => {
  test("bulk is paused for a domain above 0.3% complaints, not below, and not on small volume", () => {
    const db = openDatabase({ path: ":memory:" });
    countSender(db, "acme.test", "bulk", { delivered: 1000, complained: 2 }, T0);
    expect(reputationGuard(db, T0, 300, log)).toEqual([]);
    countSender(db, "acme.test", "bulk", { complained: 2 }, T0);
    const held = reputationGuard(db, T0, 300, log);
    expect(held.map((h) => [h.target, h.lane])).toEqual([["domain:acme.test", "bulk"]]);
    expect(held[0]?.reason).toContain("0.40%");
    expect(reputationGuard(db, T0, 300, log)).toEqual([]);
    countSender(db, "small.test", "bulk", { delivered: 50, complained: 5 }, T0);
    countSender(db, "tx.test", "transactional", { delivered: 1000, complained: 50 }, T0);
    reputationGuard(db, T0, 300, log);
    expect(activeHold(db, "domain:small.test", "bulk")).toBeNull();
    expect(activeHold(db, "domain:tx.test", "bulk")).toBeNull();
  });

  test("anomaly threshold: 10× the 7-day hourly average, never below the floor", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(anomalyThreshold(db, "k", T0, 500)).toBe(500);
    for (let h = 1; h <= 168; h++) countKeyBulk(db, "k", 100, T0 - h * 3_600_000);
    expect(anomalyThreshold(db, "k", T0, 500)).toBe(1000);
    expect(countKeyBulk(db, "k", 3, T0)).toBe(3);
    expect(countKeyBulk(db, "k", 2, T0)).toBe(5);
  });
});
