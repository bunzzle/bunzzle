import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT as P } from "../../src/accounts/projects.ts";
import { type Limits, noteLimitReached, pruneUsage, takeQuota } from "../../src/accounts/usage.ts";
import { openDatabase } from "../../src/core/store/db.ts";

const MIN = 60_000;
const T0 = Date.UTC(2026, 9, 21, 12, 0, 30);

const take = (
  db: ReturnType<typeof openDatabase>,
  limits: Partial<Limits>,
  n: number,
  now: number,
  fresh = 0,
) => takeQuota(db, P, { perHour: null, perDay: null, newPerDay: null, ...limits }, n, fresh, now);

describe("project send limits", () => {
  test("no limits: nothing is counted or stored", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(take(db, { perHour: null, perDay: null }, 5, T0)).toEqual({
      ok: true,
      near: [],
    });
    expect(db.query("SELECT * FROM project_usage").all()).toEqual([]);
  });

  test("refuses past the hourly limit and says when the oldest minute frees enough", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: 10, perDay: null };
    expect(take(db, limits, 4, T0).ok).toBe(true);
    expect(take(db, limits, 4, T0 + 10 * MIN).ok).toBe(true);
    const r = take(db, limits, 3, T0 + 20 * MIN);
    expect(r).toEqual({
      ok: false,
      over: {
        setting: "per_hour",
        window: "hour",
        limit: 10,
        used: 8,
        retryAfterMs: 60 * MIN - 30_000 - 20 * MIN,
      },
    });
    expect(take(db, limits, 2, T0 + 20 * MIN).ok).toBe(true);
    expect(take(db, limits, 1, T0 + 20 * MIN).ok).toBe(false);
    expect(take(db, limits, 4, T0 + 60 * MIN).ok).toBe(true);
  });

  test("refused email does not count; more recipients than the limit can never fit", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: 5, perDay: null };
    expect(take(db, limits, 5, T0).ok).toBe(true);
    for (let i = 0; i < 3; i++) expect(take(db, limits, 1, T0).ok).toBe(false);
    expect(take(db, limits, 1, T0 + 60 * MIN).ok).toBe(true);
    expect(take(db, limits, 6, T0 + 120 * MIN)).toMatchObject({
      ok: false,
      over: { retryAfterMs: null },
    });
  });

  test("the daily limit counts the current hour and the 23 before it", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: null, perDay: 100 };
    expect(take(db, limits, 100, T0).ok).toBe(true);
    expect(take(db, limits, 1, T0 + 23 * 60 * MIN).ok).toBe(false);
    expect(take(db, limits, 1, T0 + 24 * 60 * MIN).ok).toBe(true);
  });

  test("90 % sends one notice per window", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: 10, perDay: 1000 };
    expect(take(db, limits, 8, T0)).toEqual({ ok: true, near: [] });
    expect(take(db, limits, 1, T0)).toEqual({
      ok: true,
      near: [{ setting: "per_hour", window: "hour", limit: 10, used: 9 }],
    });
    expect(take(db, limits, 1, T0 + MIN)).toEqual({ ok: true, near: [] });
    expect(take(db, limits, 9, T0 + 61 * MIN)).toEqual({
      ok: true,
      near: [{ setting: "per_hour", window: "hour", limit: 10, used: 9 }],
    });
  });

  test("old buckets are pruned", () => {
    const db = openDatabase({ path: ":memory:" });
    take(db, { perHour: 10, perDay: 10 }, 1, T0);
    pruneUsage(db, T0 + 61 * MIN);
    expect(db.query("SELECT unit FROM project_usage").all()).toEqual([{ unit: "hour" }]);
    pruneUsage(db, T0 + 25 * 60 * MIN);
    expect(db.query("SELECT unit FROM project_usage").all()).toEqual([]);
  });

  test("new recipients have their own daily window", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { newPerDay: 10 };
    expect(take(db, limits, 50, T0, 6).ok).toBe(true);
    expect(take(db, limits, 50, T0 + MIN, 0).ok).toBe(true);
    expect(take(db, limits, 5, T0 + 2 * MIN, 5)).toEqual({
      ok: false,
      over: {
        setting: "new_recipients_per_day",
        window: "day",
        limit: 10,
        used: 6,
        retryAfterMs: 24 * 60 * MIN - 30_000 - 2 * MIN,
      },
    });
    expect(take(db, limits, 4, T0 + 2 * MIN, 3)).toEqual({
      ok: true,
      near: [{ setting: "new_recipients_per_day", window: "day", limit: 10, used: 9 }],
    });
    expect(take(db, limits, 1, T0 + 24 * 60 * MIN, 1).ok).toBe(true);
    expect(take(db, limits, 11, T0 + 25 * 60 * MIN, 11)).toMatchObject({
      ok: false,
      over: { retryAfterMs: null },
    });
  });

  test("a reached limit is noted once per window", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(noteLimitReached(db, P, "new_recipients_per_day", T0)).toBe(true);
    expect(noteLimitReached(db, P, "new_recipients_per_day", T0 + 60 * MIN)).toBe(false);
    expect(noteLimitReached(db, P, "per_hour", T0)).toBe(true);
    expect(noteLimitReached(db, P, "new_recipients_per_day", T0 + 24 * 60 * MIN)).toBe(true);
  });
});
