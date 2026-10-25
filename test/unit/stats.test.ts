import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT as A } from "../../src/accounts/projects.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import {
  countEmail,
  flushStats,
  holdStats,
  indexEmail,
  statsFor,
} from "../../src/emails/search.ts";

const T0 = Date.UTC(2026, 9, 25, 12);
const day = "2026-10-25";

function setup() {
  const db = openDatabase({ path: ":memory:" });
  db.run("PRAGMA foreign_keys = OFF");
  indexEmail(db, {
    id: "m1",
    project: A,
    domain: "a.test",
    keyId: null,
    test: false,
    tags: [{ name: "kind", value: "reset" }],
  });
  indexEmail(db, { id: "m2", project: A, domain: "b.test", keyId: null, test: false, tags: [] });
  return db;
}

const rows = (db: ReturnType<typeof setup>) =>
  (db.query("SELECT count(*) AS n FROM stats_daily").get() as { n: number }).n;

describe("daily stats", () => {
  test("held counts are summed in memory and written once on flush", () => {
    const db = setup();
    holdStats(db);
    for (let i = 0; i < 5; i++) countEmail(db, "m1", "delivered", 1, T0);
    countEmail(db, "m2", "delivered", 2, T0);
    expect(rows(db)).toBe(0);
    flushStats(db);
    expect(rows(db)).toBe(3);
    expect(statsFor(db, A, { since: day, until: day })[0]?.delivered).toBe(7);
    flushStats(db);
    expect(statsFor(db, A, { since: day, until: day })[0]?.delivered).toBe(7);
  });

  test("stats read before a flush include held counts, by tag and domain", () => {
    const db = setup();
    countEmail(db, "m1", "sent", 1, T0);
    holdStats(db);
    countEmail(db, "m1", "sent", 1, T0);
    countEmail(db, "m2", "sent", 1, T0);
    expect(statsFor(db, A, { since: day, until: day })[0]?.sent).toBe(3);
    expect(statsFor(db, A, { since: day, until: day, tag: "kind:reset" })[0]?.sent).toBe(2);
    expect(statsFor(db, A, { since: day, until: day, domain: "b.test" })[0]?.sent).toBe(1);
  });

  test("without holding, every count is written at once", () => {
    const db = setup();
    countEmail(db, "m1", "bounced", 1, T0);
    expect(rows(db)).toBe(2);
  });
});
