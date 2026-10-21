import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT as P } from "../../src/accounts/projects.ts";
import { pruneUsage, takeQuota } from "../../src/accounts/usage.ts";
import { openDatabase } from "../../src/core/store/db.ts";

const MIN = 60_000;
const T0 = Date.UTC(2026, 9, 21, 12, 0, 30);

describe("project send limits", () => {
  test("no limits: nothing is counted or stored", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(takeQuota(db, P, { perHour: null, perDay: null }, 5, T0)).toEqual({
      ok: true,
      near: [],
    });
    expect(db.query("SELECT * FROM project_usage").all()).toEqual([]);
  });

  test("refuses past the hourly limit and says when the oldest minute frees enough", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: 10, perDay: null };
    expect(takeQuota(db, P, limits, 4, T0).ok).toBe(true);
    expect(takeQuota(db, P, limits, 4, T0 + 10 * MIN).ok).toBe(true);
    const r = takeQuota(db, P, limits, 3, T0 + 20 * MIN);
    expect(r).toEqual({
      ok: false,
      over: { window: "hour", limit: 10, used: 8, retryAfterMs: 60 * MIN - 30_000 - 20 * MIN },
    });
    expect(takeQuota(db, P, limits, 2, T0 + 20 * MIN).ok).toBe(true);
    expect(takeQuota(db, P, limits, 1, T0 + 20 * MIN).ok).toBe(false);
    expect(takeQuota(db, P, limits, 4, T0 + 60 * MIN).ok).toBe(true);
  });

  test("refused email does not count; more recipients than the limit can never fit", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: 5, perDay: null };
    expect(takeQuota(db, P, limits, 5, T0).ok).toBe(true);
    for (let i = 0; i < 3; i++) expect(takeQuota(db, P, limits, 1, T0).ok).toBe(false);
    expect(takeQuota(db, P, limits, 1, T0 + 60 * MIN).ok).toBe(true);
    expect(takeQuota(db, P, limits, 6, T0 + 120 * MIN)).toMatchObject({
      ok: false,
      over: { retryAfterMs: null },
    });
  });

  test("the daily limit counts the current hour and the 23 before it", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: null, perDay: 100 };
    expect(takeQuota(db, P, limits, 100, T0).ok).toBe(true);
    expect(takeQuota(db, P, limits, 1, T0 + 23 * 60 * MIN).ok).toBe(false);
    expect(takeQuota(db, P, limits, 1, T0 + 24 * 60 * MIN).ok).toBe(true);
  });

  test("90 % sends one notice per window", () => {
    const db = openDatabase({ path: ":memory:" });
    const limits = { perHour: 10, perDay: 1000 };
    expect(takeQuota(db, P, limits, 8, T0)).toEqual({ ok: true, near: [] });
    expect(takeQuota(db, P, limits, 1, T0)).toEqual({
      ok: true,
      near: [{ window: "hour", limit: 10, used: 9 }],
    });
    expect(takeQuota(db, P, limits, 1, T0 + MIN)).toEqual({ ok: true, near: [] });
    expect(takeQuota(db, P, limits, 9, T0 + 61 * MIN)).toEqual({
      ok: true,
      near: [{ window: "hour", limit: 10, used: 9 }],
    });
  });

  test("old buckets are pruned", () => {
    const db = openDatabase({ path: ":memory:" });
    takeQuota(db, P, { perHour: 10, perDay: 10 }, 1, T0);
    pruneUsage(db, T0 + 61 * MIN);
    expect(db.query("SELECT unit FROM project_usage").all()).toEqual([{ unit: "hour" }]);
    pruneUsage(db, T0 + 25 * 60 * MIN);
    expect(db.query("SELECT unit FROM project_usage").all()).toEqual([]);
  });
});
