import { describe, expect, test } from "bun:test";
import { manualClock } from "../../src/core/clock.ts";
import { createLogger } from "../../src/core/log.ts";
import { DEFAULT_TUNING, PathControl } from "../../src/shaping/control.ts";
import { type Admission, Shaper } from "../../src/shaping/shaper.ts";

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const quiet = createLogger("error", {}, () => {});

describe("path control (H2)", () => {
  test("rate and connection limits", () => {
    const c = new PathControl({ connections: 2, ratePerSec: 5, perConnection: 100 }, T0);
    expect(c.tryAcquire(T0)).toBe(true);
    expect(c.tryAcquire(T0)).toBe(true);
    expect(c.tryAcquire(T0)).toBe(false);
    c.release(T0, "success", "");
    expect(c.tryAcquire(T0)).toBe(false);
    expect(c.nextChanceAt(T0)).toBe(T0 + 200);
    expect(c.tryAcquire(T0 + 200)).toBe(true);
    expect(c.tryAcquire(T0 + 400)).toBe(false);
  });

  const busy = (c: PathControl, t: number) => {
    let n = 0;
    while (c.tryAcquire(t)) n++;
    for (let i = 0; i < n; i++) c.release(t, "success", "");
    return n;
  };

  test("throttled: halve fast, hold 15 minutes, ignore the burst of 421s, then climb what is used", () => {
    const c = new PathControl({ connections: 8, ratePerSec: 20, perConnection: 100 }, T0);
    c.inflight = 3;
    c.release(T0, "rate", "421 4.7.0 too many connections");
    c.release(T0 + 1, "rate", "421 4.7.0 too many connections");
    c.release(T0 + 2, "rate", "421 4.7.0 too many connections");
    expect([c.rate, c.connections, c.mode]).toEqual([10, 4, "held"]);
    for (let i = 0; i < 40; i++) busy(c, T0 + 1_000 + i * 1_000);
    expect([c.rate, c.connections]).toEqual([10, 4]);
    const after = T0 + DEFAULT_TUNING.holdMs;
    let t = after;
    while (c.connections < 8 && t < after + 3_600_000) {
      t += 1_000;
      busy(c, t);
    }
    expect([c.connections, c.rate, c.mode]).toEqual([8, 10, "normal"]);
    expect(c.changes.map((x) => x.what)).toEqual([
      "halved",
      "climbed",
      "climbed",
      "climbed",
      "climbed",
    ]);
  });

  test("the rate only grows when the rate was the limit", () => {
    const c = new PathControl({ connections: 8, ratePerSec: 20, perConnection: 100 }, T0);
    c.inflight = 1;
    c.release(T0, "rate", "421");
    c.release(T0 + DEFAULT_TUNING.holdMs, "neutral", "");
    expect(c.rate).toBe(10);
    let t = T0 + DEFAULT_TUNING.holdMs;
    for (let i = 0; i < 200; i++) {
      t += 100;
      if (c.tryAcquire(t)) c.release(t, "success", "");
      c.tryAcquire(t);
      c.inflight = 0;
    }
    expect(c.rate).toBeGreaterThan(10);
    expect(c.connections).toBe(4);
  });

  test("an unused allowance never grows", () => {
    const c = new PathControl({ connections: 8, ratePerSec: 20, perConnection: 100 }, T0);
    c.inflight = 1;
    c.release(T0, "rate", "421");
    let t = T0 + DEFAULT_TUNING.holdMs;
    for (let i = 0; i < 200; i++) {
      t += 1_000;
      if (c.tryAcquire(t)) c.release(t, "success", "");
    }
    expect([c.rate, c.connections]).toEqual([10, 4]);
  });

  test("never below the floor", () => {
    const c = new PathControl({ connections: 4, ratePerSec: 4, perConnection: 100 }, T0);
    for (let i = 0; i < 20; i++) c.release(T0 + i * 20_000, "rate", "421");
    expect(c.rate).toBe(0.2);
    expect(c.connections).toBe(1);
  });

  test("blocked: pause, one probe after 15 min, restart slowly; a failed probe doubles the pause", () => {
    const c = new PathControl({ connections: 5, ratePerSec: 10, perConnection: 100 }, T0);
    c.release(T0, "reputation", "554 blocked using Spamhaus");
    expect([c.mode, c.until]).toEqual(["paused", T0 + 15 * MIN]);
    expect(c.tryAcquire(T0 + 14 * MIN)).toBe(false);
    expect(c.tryAcquire(T0 + 15 * MIN)).toBe(true);
    expect(c.mode).toBe("probing");
    expect(c.tryAcquire(T0 + 15 * MIN + 1)).toBe(false);
    c.release(T0 + 15 * MIN + 2, "reputation", "554 still blocked");
    expect([c.mode, c.until]).toEqual(["paused", T0 + 45 * MIN + 2]);
    expect(c.tryAcquire(T0 + 46 * MIN)).toBe(true);
    c.release(T0 + 46 * MIN, "success", "");
    expect([c.mode, c.rate, c.connections]).toEqual(["normal", 0.5, 1]);
    expect(c.changes.map((x) => x.what)).toEqual([
      "paused",
      "probing",
      "probe-failed",
      "probing",
      "probe-ok",
    ]);
  });

  test("state survives a restart, and a pause is never forgotten", () => {
    const c = new PathControl({ connections: 5, ratePerSec: 10, perConnection: 100 }, T0);
    c.release(T0, "reputation", "blocked");
    const again = new PathControl(c.ceiling, T0 + 1_000, DEFAULT_TUNING, c.state());
    expect([again.mode, again.until]).toEqual(["paused", T0 + 15 * MIN]);
    expect(again.tryAcquire(T0 + 2_000)).toBe(false);
  });
});

describe("shaper: lanes and waiting queues (B2, H3)", () => {
  const setup = (rate = 1, connections = 1, bulkEvery = 10) => {
    const clock = manualClock(T0);
    const shaper = new Shaper({
      log: quiet,
      clock,
      bulkEvery,
      limits: () => ({ connections, ratePerSec: rate, perConnection: 100 }),
    });
    const order: string[] = [];
    const admit = (lane: "transactional" | "bulk", name: string) =>
      shaper.admit("ip1", "example.test", null, lane).then((a: Admission) => {
        if (a.kind === "go") {
          order.push(name);
          a.release("success", "");
        } else order.push(`${name}:requeue`);
        return a;
      });
    const step = async (ms: number) => {
      clock.advance(ms);
      shaper.poke();
      await Bun.sleep(0);
    };
    return { clock, shaper, order, admit, step };
  };

  test("a transactional email overtakes waiting bulk email", async () => {
    const t = setup();
    for (let i = 0; i < 10; i++) void t.admit("bulk", `b${i}`);
    await t.step(0);
    void t.admit("transactional", "reset");
    for (let i = 0; i < 3; i++) await t.step(1_000);
    t.shaper.stop();
    expect(t.order.filter((x) => !x.endsWith(":requeue")).slice(0, 3)).toEqual([
      "b0",
      "reset",
      "b1",
    ]);
  });

  test("bulk still gets a guaranteed share", async () => {
    const t = setup(1, 1, 5);
    for (let i = 0; i < 10; i++) void t.admit("bulk", `b${i}`);
    for (let i = 0; i < 10; i++) void t.admit("transactional", `t${i}`);
    for (let i = 0; i < 12; i++) {
      void t.admit("bulk", `r${i}`);
      await t.step(1_000);
    }
    t.shaper.stop();
    const served = t.order.filter((x) => !x.endsWith(":requeue")).slice(0, 11);
    expect(served.filter((x) => !x.startsWith("t")).length).toBe(3);
  });

  test("bulk over the path's budget goes back to the database at spaced slots", async () => {
    const t = setup();
    const all = Array.from({ length: 6 }, () =>
      t.shaper.admit("ip1", "example.test", null, "bulk"),
    );
    expect(t.shaper.blocked().full).toEqual(["ip1|example.test"]);
    const back = await Promise.all(all.slice(2));
    expect(back.map((a) => (a.kind === "requeue" ? a.delayMs : null))).toEqual([
      1_000, 2_000, 3_000, 4_000,
    ]);
    t.shaper.stop();
  });

  test("a slow path gets a smaller bulk budget than its rate allows", async () => {
    const t = setup(5, 5);
    const slow = Array.from({ length: 1 }, () =>
      t.shaper.admit("ip1", "example.test", null, "bulk"),
    );
    const tickets = await Promise.all(slow);
    t.clock.advance(3_000);
    for (const a of tickets) if (a.kind === "go") a.release("success", "");
    const kinds: string[] = [];
    for (let i = 0; i < 12; i++) {
      void t.shaper.admit("ip1", "example.test", null, "bulk").then((a) => kinds.push(a.kind));
    }
    await t.step(0);
    expect(kinds.filter((k) => k === "requeue").length).toBe(5);
    t.shaper.stop();
  });

  test("a fast path sends on as few connections as its rate needs", async () => {
    const t = setup(5, 5);
    const warm = await Promise.all(
      Array.from({ length: 1 }, () => t.shaper.admit("ip1", "example.test", null, "bulk")),
    );
    t.clock.advance(12);
    for (const a of warm) if (a.kind === "go") a.release("success", "");
    t.clock.advance(1_000);
    const kinds: string[] = [];
    for (let i = 0; i < 5; i++) {
      void t.shaper.admit("ip1", "example.test", null, "bulk").then((a) => kinds.push(a.kind));
    }
    await t.step(0);
    expect(kinds).toEqual(["go"]);
    expect(t.shaper.views()[0]?.inflight).toBe(1);
    t.shaper.stop();
  });

  test("a transactional email on a new path starts while the first bulk send is out", async () => {
    const t = setup(100, 4);
    const first = await t.shaper.admit("ip1", "example.test", null, "bulk");
    expect(first.kind).toBe("go");
    const kinds: string[] = [];
    void t.shaper
      .admit("ip1", "example.test", null, "bulk")
      .then((a) => kinds.push(`bulk ${a.kind}`));
    void t.shaper
      .admit("ip1", "example.test", null, "transactional")
      .then((a) => kinds.push(`transactional ${a.kind}`));
    await t.step(0);
    expect(kinds).toEqual(["transactional go"]);
    expect(t.shaper.views()[0]).toMatchObject({
      inflight: 2,
      waiting: { transactional: 0, bulk: 1 },
    });
    t.shaper.stop();
  });

  test("slow paths leave a quarter of the delivery slots to other paths", async () => {
    const clock = manualClock(T0);
    const shaper = new Shaper({
      log: quiet,
      clock,
      slots: 4,
      limits: () => ({ connections: 5, ratePerSec: 5, perConnection: 100 }),
    });
    const warm = await shaper.admit("ip1", "slow.test", null, "bulk");
    clock.advance(3_000);
    if (warm.kind === "go") warm.release("success", "");
    const slow = [1, 2, 3, 4].map(() => shaper.admit("ip1", "slow.test", null, "bulk"));
    const fast = [1, 2, 3].map(() => shaper.admit("ip1", "fast.test", null, "bulk"));
    expect(shaper.blocked().full).toEqual(["ip1|slow.test"]);
    const kinds = async (all: Promise<Admission>[]) => (await Promise.all(all)).map((a) => a.kind);
    expect(await kinds(slow)).toEqual(["go", "go", "go", "requeue"]);
    expect((await fast[0])?.kind).toBe("go");
    shaper.stop();
  });

  test("transactional pushes waiting bulk out when the queue is full", async () => {
    const t = setup();
    void t.admit("bulk", "b0");
    void t.admit("bulk", "b1");
    for (let i = 0; i < 20; i++) void t.admit("transactional", `t${i}`);
    await t.step(0);
    expect(t.order).toContain("b1:requeue");
    t.shaper.stop();
  });

  test("a waiter not served before its deadline goes back to the database", async () => {
    const t = setup(0.001, 1);
    const first = await t.shaper.admit("ip1", "example.test", null, "bulk");
    expect(first.kind).toBe("go");
    const late = await t.shaper.admit("ip1", "example.test", null, "transactional", 20);
    expect(late).toMatchObject({ kind: "requeue", reason: "example.test busy" });
    expect(t.shaper.views()[0]?.waiting).toEqual({ transactional: 0, bulk: 0 });
    t.shaper.stop();
  });

  test("even transactional email is capped per path, so one slow site can't hold every slot", async () => {
    const t = setup(0.001, 1);
    const all = Array.from({ length: 45 }, () =>
      t.shaper.admit("ip1", "example.test", null, "transactional", 60_000),
    );
    expect(t.shaper.blocked().paused).toEqual(["ip1|example.test"]);
    const extra = await t.shaper.admit("ip1", "example.test", null, "transactional");
    expect(extra).toMatchObject({ kind: "requeue", reason: "example.test queue full" });
    t.shaper.stop();
    expect((await Promise.all(all)).filter((a) => a.kind === "requeue").length).toBe(44);
  });

  test("a pause sends every waiter back with the pause as delay", async () => {
    const t = setup(10, 1);
    const first = await t.shaper.admit("ip1", "example.test", null, "bulk");
    const waiting = t.shaper.admit("ip1", "example.test", null, "transactional");
    if (first.kind !== "go") throw new Error("expected go");
    first.release("reputation", "blocked");
    const w = await waiting;
    expect(w).toMatchObject({ kind: "requeue", delayMs: 15 * MIN, blocked: true });
    const later = await t.shaper.admit("ip1", "example.test", null, "transactional");
    expect(later.kind).toBe("requeue");
    expect(t.shaper.blocked().paused).toEqual(["ip1|example.test"]);
    expect(t.shaper.views()[0]?.changes.map((c) => c.what)).toEqual(["paused"]);
    t.shaper.stop();
  });
});
