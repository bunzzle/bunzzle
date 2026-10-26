import { Database, type Statement } from "bun:sqlite";
import type { Migration } from "./migrations/index.ts";
import { migrations as defaultMigrations } from "./migrations/index.ts";

export interface OpenOptions {
  path: string;
  migrations?: readonly Migration[];
}

const STATEMENTS = 1024;

function holdStatements(db: Database): void {
  const held = new Map<string, Statement>();
  db.query = ((sql: string) => {
    const known = held.get(sql);
    if (known) return known;
    const s = db.prepare(sql);
    if (held.size < STATEMENTS) held.set(sql, s);
    return s;
  }) as Database["query"];
}

export function openDatabase({ path, migrations = defaultMigrations }: OpenOptions): Database {
  const db = new Database(path, { create: true, strict: true });
  holdStatements(db);
  db.run("PRAGMA journal_mode = WAL");
  db.run("PRAGMA synchronous = FULL");
  db.run("PRAGMA foreign_keys = ON");
  db.run("PRAGMA secure_delete = ON");
  db.run("PRAGMA busy_timeout = 5000");
  db.run("PRAGMA temp_store = MEMORY");
  migrate(db, migrations);
  return db;
}

export function migrate(db: Database, migrations: readonly Migration[]): number[] {
  assertOrdered(migrations);
  db.run(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at INTEGER NOT NULL
  ) STRICT`);

  const applied = new Set(
    db
      .query<{ version: number }, []>("SELECT version FROM schema_migrations")
      .all()
      .map((r) => r.version),
  );
  const record = db.query<unknown, [number, string, number]>(
    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
  );

  const done: number[] = [];
  for (const m of migrations) {
    if (applied.has(m.version)) continue;
    db.transaction(() => {
      db.run(m.sql);
      record.run(m.version, m.name, Date.now());
    })();
    done.push(m.version);
  }
  return done;
}

function assertOrdered(migrations: readonly Migration[]) {
  migrations.forEach((m, i) => {
    if (m.version !== i + 1) {
      throw new Error(`migration versions must be 1..n with no gaps; got ${m.version} at ${i}`);
    }
  });
}
