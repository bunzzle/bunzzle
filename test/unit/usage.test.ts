import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT as P } from "../../src/accounts/projects.ts";
import {
  type Limits,
  newRecipientsLimit,
  noteLimitReached,
  pruneUsage,
  takeQuota,
} from "../../src/accounts/usage.ts";
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
  test("no limits: only first-time recipients are counted", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(take(db, { perHour: null, perDay: null }, 5, T0)).toEqual({
      ok: true,
      near: [],
    });
    expect(db.query("SELECT * FROM project_usage").all()).toEqual([]);
    expect(take(db, {}, 5, T0, 3)).toEqual({ ok: true, near: [] });
    expect(db.query("SELECT unit, n FROM project_usage").all()).toEqual([
      { unit: "new_hour", n: 3 },
    ]);
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

describe("adaptive first-time recipient limit", () => {
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;
  const TODAY = Math.floor(T0 / DAY) * DAY;
  const project = (newRecipientsPerDay: number | null, newRecipientsAuto: boolean) => ({
    id: P,
    newRecipientsPerDay,
    newRecipientsAuto,
  });
  const used = (db: ReturnType<typeof openDatabase>, at: number, n: number) =>
    db.run("INSERT INTO project_usage (project_id, unit, slot, n) VALUES (?, 'new_hour', ?, ?)", [
      P,
      Math.floor(at / HOUR),
      n,
    ]);

  test("an explicit limit wins, no limit when both are off", () => {
    const db = openDatabase({ path: ":memory:" });
    used(db, TODAY - DAY, 1_000);
    expect(newRecipientsLimit(db, project(50, true), T0)).toBe(50);
    expect(newRecipientsLimit(db, project(50, false), T0)).toBe(50);
    expect(newRecipientsLimit(db, project(null, false), T0)).toBeNull();
  });

  test("200 without history, then three times the busiest of the last 14 days", () => {
    expect(newRecipientsLimit(openDatabase({ path: ":memory:" }), project(null, true), T0)).toBe(
      200,
    );
    const db = openDatabase({ path: ":memory:" });
    used(db, TODAY - 15 * DAY, 5_000);
    used(db, T0, 5_000);
    used(db, TODAY - 3 * DAY + HOUR, 30);
    used(db, TODAY - 3 * DAY + 20 * HOUR, 40);
    used(db, TODAY - 14 * DAY, 90);
    used(db, TODAY - 2 * DAY, 80);
    expect(newRecipientsLimit(db, project(null, true), T0)).toBe(270);
    expect(newRecipientsLimit(db, project(null, true), T0 + HOUR)).toBe(270);
    expect(newRecipientsLimit(db, project(null, true), T0 + DAY)).toBe(15_000);
  });

  test("first-time recipient counts are kept 15 days", () => {
    const db = openDatabase({ path: ":memory:" });
    used(db, T0 - 15 * DAY + HOUR, 1);
    used(db, T0 - 15 * DAY, 2);
    db.run("INSERT INTO project_usage (project_id, unit, slot, n) VALUES (?, 'hour', ?, 3)", [
      P,
      Math.floor((T0 - 2 * DAY) / HOUR),
    ]);
    pruneUsage(db, T0);
    expect(db.query("SELECT unit, n FROM project_usage").all()).toEqual([
      { unit: "new_hour", n: 1 },
    ]);
  });
});
