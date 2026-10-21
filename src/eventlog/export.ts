import type { Database } from "bun:sqlite";
import type { EventLog } from "./log.ts";

const CURSOR = "event_log_cursor";
const ADMIN_CURSOR = "admin_event_log_cursor";

interface Row {
  id: number;
  message_id: string;
  kind: string;
  data: string | null;
  source: string;
  occurred_at: number;
}

export interface Batch {
  lines: string[];
  last: number;
}

function cursor(db: Database, key = CURSOR): number | null {
  const v = db
    .query<{ value: string }, [string]>("SELECT value FROM settings WHERE key = ?")
    .get(key)?.value;
  return v === undefined ? null : Number(v);
}

export function setCursor(db: Database, id: number, now: number, key = CURSOR): void {
  db.query<unknown, [string, string, number]>(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
  ).run(key, String(id), now);
}

export function beginAtEnd(db: Database, now: number): void {
  if (cursor(db) === null) {
    const last = db.query<{ id: number | null }, []>("SELECT max(id) AS id FROM events").get()?.id;
    setCursor(db, last ?? 0, now);
  }
  if (cursor(db, ADMIN_CURSOR) === null) {
    const last = db
      .query<{ id: number | null }, []>("SELECT max(id) AS id FROM admin_events")
      .get()?.id;
    setCursor(db, last ?? 0, now, ADMIN_CURSOR);
  }
}

interface AdminRow {
  id: number;
  kind: string;
  project_id: string;
  actor: string;
  data: string | null;
  occurred_at: number;
}

export function nextAdminBatch(db: Database, limit = 1000): Batch | null {
  const rows = db
    .query<AdminRow, [number, number]>(
      `SELECT id, kind, project_id, actor, data, occurred_at FROM admin_events
       WHERE id > ? ORDER BY id LIMIT ?`,
    )
    .all(cursor(db, ADMIN_CURSOR) ?? 0, limit);
  if (rows.length === 0) return null;
  return {
    lines: rows.map((r) =>
      JSON.stringify({
        admin_event_id: r.id,
        at: new Date(r.occurred_at).toISOString(),
        project_id: r.project_id,
        event: r.kind,
        source: "admin",
        actor: r.actor,
        data: r.data === null ? {} : JSON.parse(r.data),
      }),
    ),
    last: (rows.at(-1) as AdminRow).id,
  };
}

export function nextBatch(db: Database, limit = 1000): Batch | null {
  const rows = db
    .query<Row, [number, number]>(
      "SELECT id, message_id, kind, data, source, occurred_at FROM events WHERE id > ? ORDER BY id LIMIT ?",
    )
    .all(cursor(db) ?? 0, limit);
  if (rows.length === 0) return null;
  return {
    lines: rows.map((r) =>
      JSON.stringify({
        id: r.id,
        at: new Date(r.occurred_at).toISOString(),
        email_id: r.message_id,
        event: r.kind,
        source: r.source,
        data: r.data === null ? {} : JSON.parse(r.data),
      }),
    ),
    last: (rows.at(-1) as Row).id,
  };
}

export async function exportEvents(
  run: <T>(fn: (db: Database) => T) => Promise<T>,
  file: EventLog,
  now: () => number,
): Promise<void> {
  for (let i = 0; i < 20; i++) {
    const admin = await run((d) => nextAdminBatch(d));
    if (admin) {
      await file.write(admin.lines, now());
      await run((d) => setCursor(d, admin.last, now(), ADMIN_CURSOR));
    }
    const batch = await run((d) => nextBatch(d));
    if (!batch && !admin) return file.roll(now());
    if (!batch) continue;
    await file.write(batch.lines, now());
    await run((d) => setCursor(d, batch.last, now()));
  }
}
