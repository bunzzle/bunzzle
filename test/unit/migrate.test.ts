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

  test("upgrading an M2 queue keeps every job and its state", () => {
    const db = new Database(":memory:", { strict: true });
    db.run("PRAGMA foreign_keys = ON");
    migrate(db, migrations.slice(0, 2));
    db.run(
      "INSERT INTO messages (id, type, payload, created_at) VALUES ('m1', 't', '1', 5), ('m2', 't', '2', 6)",
    );
    db.run(`INSERT INTO jobs (message_id, state, run_after, attempt, last_error, updated_at)
            VALUES ('m1', 'ready', 10, 2, 'busy', 7), ('m2', 'unknown', 11, 1, NULL, 8)`);
    expect(migrate(db, migrations)).toEqual([
      3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    ]);
    const rows = db
      .query<Record<string, unknown>, []>(
        "SELECT id, message_id, target, state, run_after, attempt, last_error, expires_at, notices FROM jobs ORDER BY id",
      )
      .all();
    expect(rows).toEqual([
      {
        id: "m1",
        message_id: "m1",
        target: "",
        state: "ready",
        run_after: 10,
        attempt: 2,
        last_error: "busy",
        expires_at: null,
        notices: 0,
      },
      {
        id: "m2",
        message_id: "m2",
        target: "",
        state: "unknown",
        run_after: 11,
        attempt: 1,
        last_error: null,
        expires_at: null,
        notices: 0,
      },
    ]);
    expect(db.query("PRAGMA foreign_key_check").all()).toEqual([]);
  });

  test("upgrading to projects puts every existing row and key in the default project", () => {
    const db = new Database(":memory:", { strict: true });
    db.run("PRAGMA foreign_keys = ON");
    migrate(db, migrations.slice(0, 20));
    db.run("INSERT INTO messages (id, type, payload, created_at) VALUES ('m1', 't', '1', 5)");
    db.run(
      "INSERT INTO jobs (id, message_id, state, run_after, updated_at) VALUES ('j1', 'm1', 'ready', 1, 1)",
    );
    db.run("INSERT INTO email_index (message_id, domain) VALUES ('m1', 'a.test')");
    db.run(`INSERT INTO api_keys (id, name, token_hash, prefix, scope, rate_limit, created_at)
            VALUES ('k1', 'k', 'h', 'p', 'full', 10, 1)`);
    db.run(`INSERT INTO domains (name, status, records, created_at, updated_at)
            VALUES ('a.test', 'verified', '[]', 1, 1)`);
    db.run(
      "INSERT INTO stats_daily (day, domain, tag, metric, n) VALUES ('2026-10-21', 'a.test', '', 'sent', 1)",
    );
    db.run(
      "INSERT INTO webhooks (id, url, events, created_at) VALUES ('w1', 'https://h.test', '[]', 1)",
    );
    db.run(
      "INSERT INTO routes (id, address, url, format, created_at) VALUES ('r1', 'in@a.test', 'https://h.test', 'raw', 1)",
    );
    db.run(
      "INSERT INTO templates (id, name, version, created_at, updated_at) VALUES ('t1', 'welcome', 1, 1, 1)",
    );
    db.run(
      "INSERT INTO suppressions (address, scope, reason, created_at) VALUES ('x@b.test', 'all', 'bounce', 1)",
    );

    expect(migrate(db, migrations)).toEqual([21, 22, 23, 24, 25, 26]);
    expect(db.query("SELECT id, name, suspended_at, deleted_at FROM projects").all()).toEqual([
      { id: "default", name: "default", suspended_at: null, deleted_at: null },
    ]);
    for (const table of [
      "messages",
      "jobs",
      "email_index",
      "api_keys",
      "domains",
      "stats_daily",
      "webhooks",
      "routes",
      "templates",
      "suppressions",
    ]) {
      expect(db.query(`SELECT DISTINCT project_id FROM ${table}`).all()).toEqual([
        { project_id: "default" },
      ]);
    }
    expect(db.query("PRAGMA foreign_key_check").all()).toEqual([]);
  });

  test("template names are unique per project", () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("INSERT INTO projects (id, name, created_at) VALUES ('p2', 'other', 1)");
    const add = db.query<unknown, [string, string]>(
      "INSERT INTO templates (id, name, version, created_at, updated_at, project_id) VALUES (?, 'welcome', 1, 1, 1, ?)",
    );
    add.run("t1", "default");
    add.run("t2", "p2");
    expect(() => add.run("t3", "p2")).toThrow(/UNIQUE/);
  });

  test("rejects gaps in version numbers", () => {
    const db = new Database(":memory:");
    expect(() => migrate(db, [{ version: 2, name: "x", sql: "SELECT 1" }])).toThrow(/no gaps/);
  });

  test("uses WAL, synchronous=FULL and in-memory temp storage on file databases", () => {
    const path = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-test-${crypto.randomUUID()}.db`;
    const db = openDatabase({ path });
    expect(db.query<{ journal_mode: string }, []>("PRAGMA journal_mode").get()?.journal_mode).toBe(
      "wal",
    );
    expect(db.query<{ synchronous: number }, []>("PRAGMA synchronous").get()?.synchronous).toBe(2);
    expect(db.query<{ temp_store: number }, []>("PRAGMA temp_store").get()?.temp_store).toBe(2);
    db.close();
  });
});
