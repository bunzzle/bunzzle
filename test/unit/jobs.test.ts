import type { Database } from "bun:sqlite";
import { beforeEach, describe, expect, test } from "bun:test";
import { eventsFor } from "../../src/core/events.ts";
import {
  claim,
  countByState,
  enqueue,
  expireLeases,
  nextWakeAt,
  pendingCount,
  recoverAfterCrash,
  resendUnresolved,
  type SettleOptions,
  settle,
} from "../../src/core/jobs.ts";
import { defer, fail, type Outcome, ok, unknown } from "../../src/core/outcome.ts";
import { clampHint, defaultRetryPolicy, retryDelay } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";

const T0 = 1_700_000_000_000;
const opts: SettleOptions = { retry: defaultRetryPolicy, reconcileMs: 900_000, random: () => 0.5 };

let db: Database;
const job = (id: string) =>
  db
    .query<Record<string, unknown>, [string]>("SELECT * FROM jobs WHERE message_id = ?")
    .get(id) as Record<string, unknown>;
const kinds = (id: string) => eventsFor(db, id).map((e) => e.kind);

beforeEach(() => {
  db = openDatabase({ path: ":memory:" });
});

describe("enqueue", () => {
  test("stores message, ready job and queued event", () => {
    const id = enqueue(db, { type: "email", payload: { to: "a@b.c" }, metadata: { k: 1 } }, T0);
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(job(id)).toMatchObject({ state: "ready", attempt: 0, run_after: T0, priority: 0 });
    expect(kinds(id)).toEqual(["queued"]);
  });

  test("one job per target, all sharing the message", () => {
    const id = enqueue(
      db,
      { id: "m", type: "email", payload: 1, targets: ["a.test", "b.test", "a.test"] },
      T0,
    );
    const rows = db
      .query<{ id: string; target: string }, [string]>(
        "SELECT id, target FROM jobs WHERE message_id = ? ORDER BY id",
      )
      .all(id);
    expect(rows).toEqual([
      { id: "m/a.test", target: "a.test" },
      { id: "m/b.test", target: "b.test" },
    ]);
    const claimed = claim(db, T0, 10, 1_000);
    expect(claimed.map((j) => [j.id, j.messageId, j.target, j.payload])).toEqual([
      ["m/a.test", "m", "a.test", 1],
      ["m/b.test", "m", "b.test", 1],
    ]);
  });

  test("rejects a duplicate id", () => {
    enqueue(db, { id: "m1", type: "t", payload: 1 }, T0);
    expect(() => enqueue(db, { id: "m1", type: "t", payload: 1 }, T0)).toThrow();
  });
});

describe("claim", () => {
  test("leases runnable jobs by priority then age and returns their messages", () => {
    enqueue(db, { id: "late", type: "t", payload: "x", runAfter: T0 + 1 }, T0);
    enqueue(db, { id: "low", type: "t", payload: "l", priority: 5 }, T0);
    enqueue(db, { id: "old", type: "t", payload: "o", runAfter: T0 - 10 }, T0);
    enqueue(db, { id: "new", type: "t", payload: "n" }, T0);

    const claimed = claim(db, T0, 2, 30_000);
    expect(claimed.map((j) => j.id).sort()).toEqual(["new", "old"]);
    expect(claimed.find((j) => j.id === "old")).toMatchObject({ payload: "o", attempt: 1 });
    expect(job("old")).toMatchObject({ state: "leased", lease_until: T0 + 30_000 });

    expect(claim(db, T0, 10, 30_000).map((j) => j.id)).toEqual(["low"]);
    expect(claim(db, T0, 10, 30_000)).toEqual([]);
    expect(claim(db, T0 + 1, 10, 30_000).map((j) => j.id)).toEqual(["late"]);
  });
});

describe("settle", () => {
  const leased = (id = "m") => {
    enqueue(db, { id, type: "t", payload: 1 }, T0);
    const [j] = claim(db, T0, 1, 30_000);
    if (!j) throw new Error("nothing claimed");
    return j;
  };

  test("done", () => {
    const j = leased();
    expect(settle(db, j, ok.done, T0 + 5, opts)).toBe("done");
    expect(job("m")).toMatchObject({ state: "done", lease_until: null });
    expect(kinds("m")).toEqual(["queued", "done"]);
  });

  test("fail is dead", () => {
    const j = leased();
    expect(settle(db, j, fail("rejected", "bad address"), T0, opts)).toBe("dead");
    expect(job("m")).toMatchObject({ state: "dead", last_error: "rejected: bad address" });
  });

  test("defer goes back to ready on the retry schedule", () => {
    const j = leased();
    expect(settle(db, j, defer("503"), T0, opts)).toBe("retry");
    expect(job("m")).toMatchObject({ state: "ready", run_after: T0 + 60_000, last_error: "503" });
  });

  test("defer honours an explicit delay", () => {
    const j = leased();
    settle(db, j, defer("throttled", 1_000), T0, opts);
    expect(job("m")["run_after"]).toBe(T0 + 1_000);
  });

  test("defer after the last attempt is dead", () => {
    const j = leased();
    const last = { ...j, attempt: defaultRetryPolicy.maxAttempts };
    db.run("UPDATE jobs SET attempt = ? WHERE message_id = 'm'", [last.attempt]);
    expect(settle(db, last, defer("503"), T0, opts)).toBe("dead");
    expect(eventsFor(db, "m").at(-1)?.data).toMatchObject({ code: "retries_exhausted" });
  });

  test("defer after the maximum age is dead", () => {
    const j = leased();
    expect(settle(db, j, defer("503"), T0 + defaultRetryPolicy.maxAgeMs, opts)).toBe("dead");
  });

  test("defer after the per-message expiry is dead with code expired", () => {
    enqueue(db, { id: "m", type: "t", payload: 1, expiresAt: T0 + 120_000 }, T0);
    const [j] = claim(db, T0, 1, 30_000);
    if (!j) throw new Error("nothing claimed");
    expect(j.expiresAt).toBe(T0 + 120_000);
    expect(settle(db, j, defer("busy", 3_600_000), T0, opts)).toBe("retry");
    expect(job("m")["run_after"]).toBe(T0 + 120_000);
    const [again] = claim(db, T0 + 120_000, 1, 30_000);
    if (!again) throw new Error("nothing claimed");
    expect(settle(db, again, defer("busy"), T0 + 120_000, opts)).toBe("dead");
    expect(eventsFor(db, "m").at(-1)?.data).toMatchObject({ code: "expired" });
  });

  test("delayed notices fire once each after 1 hour and 1 day", () => {
    enqueue(db, { id: "m", type: "t", payload: 1 }, T0);
    const step = (now: number) => {
      const [j] = claim(db, now, 1, 30_000);
      if (!j) throw new Error("nothing claimed");
      settle(db, j, defer("busy", 0), now, opts);
    };
    step(T0 + 1_000);
    step(T0 + 3_600_000);
    step(T0 + 3_700_000);
    step(T0 + 30 * 3_600_000);
    const delayed = eventsFor(db, "m")
      .filter((e) => e.kind === "delayed")
      .map((e) => e.data?.["after_ms"]);
    expect(delayed).toEqual([3_600_000, 86_400_000]);
    expect(job("m")["notices"]).toBe(2);
  });

  test("apply runs in the same write, with the settled state, and not when stale", () => {
    const j = leased();
    const seen: string[] = [];
    const outcome: Outcome = {
      ...defer("busy"),
      apply: (d, settled, now) => {
        seen.push(`${settled}@${now}`);
        d.run("INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', ?)", [now]);
      },
    };
    expect(settle(db, j, outcome, T0 + 7, opts)).toBe("retry");
    expect(settle(db, j, outcome, T0 + 8, opts)).toBe("stale");
    expect(seen).toEqual([`retry@${T0 + 7}`]);
  });

  test("unknown waits for reconciliation", () => {
    const j = leased();
    expect(settle(db, j, unknown("timeout"), T0, opts)).toBe("unknown");
    expect(job("m")).toMatchObject({ state: "unknown", check_after: T0 + opts.reconcileMs });
  });

  test("a late success resolves an unknown job", () => {
    const j = leased();
    settle(db, j, unknown("timeout"), T0, opts);
    expect(settle(db, j, ok.done, T0 + 1, opts)).toBe("done");
  });

  test("outcomes for an old attempt or a finished job are stale", () => {
    const j = leased();
    settle(db, j, defer("503", 0), T0, opts);
    const [again] = claim(db, T0, 1, 30_000);
    if (!again) throw new Error("nothing claimed");
    expect(again.attempt).toBe(2);
    expect(settle(db, j, ok.done, T0, opts)).toBe("stale");
    expect(settle(db, again, ok.done, T0, opts)).toBe("done");
    expect(settle(db, again, fail("x", "y"), T0, opts)).toBe("stale");
    expect(job("m")["state"]).toBe("done");
  });
});

describe("leases and reconciliation", () => {
  test("expired leases become unknown, then ready with a duplicate_risk event", () => {
    enqueue(db, { id: "m", type: "t", payload: 1 }, T0);
    claim(db, T0, 1, 1_000);
    expect(expireLeases(db, T0 + 999, 5_000)).toBe(0);
    expect(expireLeases(db, T0 + 1_000, 5_000)).toBe(1);
    expect(job("m")).toMatchObject({ state: "unknown", check_after: T0 + 6_000 });
    expect(resendUnresolved(db, T0 + 5_999)).toBe(0);
    expect(resendUnresolved(db, T0 + 6_000)).toBe(1);
    expect(job("m")).toMatchObject({ state: "ready", run_after: T0 + 6_000 });
    expect(kinds("m")).toEqual(["queued", "unknown", "duplicate_risk"]);
  });

  test("recovery after a crash marks every lease unknown", () => {
    enqueue(db, { id: "a", type: "t", payload: 1 }, T0);
    enqueue(db, { id: "b", type: "t", payload: 1 }, T0);
    claim(db, T0, 2, 3_600_000);
    expect(recoverAfterCrash(db, T0, 0)).toBe(2);
    expect(countByState(db)).toMatchObject({ unknown: 2, leased: 0 });
    expect(pendingCount(db)).toBe(2);
  });

  test("nextWakeAt is the earliest pending deadline", () => {
    expect(nextWakeAt(db)).toBeUndefined();
    enqueue(db, { id: "a", type: "t", payload: 1, runAfter: T0 + 500 }, T0);
    enqueue(db, { id: "b", type: "t", payload: 1 }, T0);
    claim(db, T0, 1, 200);
    expect(nextWakeAt(db)).toBe(T0 + 200);
  });
});

describe("retry schedule", () => {
  const mid = () => 0.5;

  test("1, 5, 15, 30 minutes, then hourly", () => {
    expect([1, 2, 3, 4, 5, 50].map((n) => retryDelay(defaultRetryPolicy, n, mid))).toEqual([
      60_000, 300_000, 900_000, 1_800_000, 3_600_000, 3_600_000,
    ]);
  });

  test("jitter stays within 10%", () => {
    expect(retryDelay(defaultRetryPolicy, 5, () => 0)).toBe(3_240_000);
    expect(retryDelay(defaultRetryPolicy, 5, () => 1)).toBe(3_960_000);
  });

  test("about 124 attempts, the last one near day 5, no gap over an hour", () => {
    let t = 0;
    let attempts = 1;
    let gap = 0;
    while (true) {
      const d = retryDelay(defaultRetryPolicy, attempts, mid);
      if (t + d >= defaultRetryPolicy.maxAgeMs) break;
      t += d;
      gap = Math.max(gap, d);
      attempts++;
    }
    expect(attempts).toBe(124);
    expect(t / 3_600_000).toBeGreaterThan(119);
    expect(gap).toBe(3_600_000);
  });

  test("server hints are clamped between 1 minute and 1 hour", () => {
    expect(clampHint(5_000)).toBe(60_000);
    expect(clampHint(300_000)).toBe(300_000);
    expect(clampHint(86_400_000)).toBe(3_600_000);
  });
});
