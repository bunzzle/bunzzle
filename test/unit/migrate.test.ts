import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { migrate, openDatabase } from "../../src/core/store/db.ts";
import { migrations } from "../../src/core/store/migrations/index.ts";

const versions = (db: Database) =>
  db
    .query<{ version: number }, []>("SELECT version FROM schema_migrations ORDER BY version")
    .all()
    .map((r) => r.version);

describe("migrate", () => {
  test("applies all migrations on a fresh database", () => {
    const db = openDatabase({ path: ":memory:" });
    expect(versions(db)).toEqual(migrations.map((m) => m.version));
    expect(db.query("SELECT name FROM sqlite_master WHERE name = 'settings'").get()).toBeTruthy();
  });

  test("is idempotent", () => {
    const db = new Database(":memory:");
    expect(migrate(db, migrations).length).toBe(migrations.length);
    expect(migrate(db, migrations)).toEqual([]);
  });

  test("applies only new migrations", () => {
    const db = new Database(":memory:");
    migrate(db, [{ version: 1, name: "a", sql: "CREATE TABLE a (x INTEGER)" }]);
    const applied = migrate(db, [
      { version: 1, name: "a", sql: "CREATE TABLE a (x INTEGER)" },
      { version: 2, name: "b", sql: "CREATE TABLE b (x INTEGER)" },
    ]);
    expect(applied).toEqual([2]);
  });

  test("runs every statement in a multi-statement migration", () => {
    const db = new Database(":memory:");
    migrate(db, [
      { version: 1, name: "two", sql: "CREATE TABLE a (x INTEGER);\nCREATE TABLE b (y INTEGER);" },
    ]);
    const tables = db
      .query<{ name: string }, []>("SELECT name FROM sqlite_master WHERE name IN ('a','b')")
      .all()
      .map((r) => r.name)
      .sort();
    expect(tables).toEqual(["a", "b"]);
  });

  test("a failing migration leaves nothing behind", () => {
    const db = new Database(":memory:");
    expect(() =>
      migrate(db, [{ version: 1, name: "bad", sql: "CREATE TABLE ok (x); NOT VALID SQL" }]),
    ).toThrow();
    expect(versions(db)).toEqual([]);
    expect(db.query("SELECT name FROM sqlite_master WHERE name = 'ok'").get()).toBeNull();
  });

  test("rejects gaps in version numbers", () => {
    const db = new Database(":memory:");
    expect(() => migrate(db, [{ version: 2, name: "x", sql: "SELECT 1" }])).toThrow(/no gaps/);
  });

  test("uses WAL and synchronous=FULL on file databases", () => {
    const path = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-test-${crypto.randomUUID()}.db`;
    const db = openDatabase({ path });
    expect(db.query<{ journal_mode: string }, []>("PRAGMA journal_mode").get()?.journal_mode).toBe(
      "wal",
    );
    expect(db.query<{ synchronous: number }, []>("PRAGMA synchronous").get()?.synchronous).toBe(2);
    db.close();
  });
});
