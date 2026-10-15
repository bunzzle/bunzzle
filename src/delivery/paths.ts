import type { Database } from "bun:sqlite";

export type PathState = "open" | "slowed" | "paused";

export interface Path {
  source: string;
  site: string;
  state: PathState;
  until: number | null;
  reason: string | null;
  pauses: number;
}

interface PathRow {
  state: PathState;
  until: number | null;
  reason: string | null;
  pauses: number;
}

export function getPath(db: Database, source: string, site: string, now: number): Path {
  const row = db
    .query<PathRow, [string, string]>(
      "SELECT state, until, reason, pauses FROM paths WHERE source = ? AND site = ?",
    )
    .get(source, site);
  if (!row) return { source, site, state: "open", until: null, reason: null, pauses: 0 };
  if (row.state !== "open" && row.until !== null && row.until <= now) {
    return { source, site, state: "open", until: null, reason: null, pauses: row.pauses };
  }
  return { source, site, ...row };
}

function save(db: Database, p: Path, now: number) {
  db.query<unknown, [string, string, PathState, number | null, string | null, number, number]>(
    `INSERT INTO paths (source, site, state, until, reason, pauses, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (source, site) DO UPDATE SET state = excluded.state, until = excluded.until,
       reason = excluded.reason, pauses = excluded.pauses, updated_at = excluded.updated_at`,
  ).run(p.source, p.site, p.state, p.until, p.reason, p.pauses, now);
}

export function pauseDuration(pauses: number, baseMs: number, maxMs: number): number {
  return Math.min(maxMs, baseMs * 2 ** pauses);
}

export function pausePath(db: Database, p: Path, until: number, reason: string, now: number) {
  const current = getPath(db, p.source, p.site, now);
  save(db, { ...current, state: "paused", until, reason, pauses: current.pauses + 1 }, now);
}

export function slowPath(db: Database, p: Path, until: number, reason: string, now: number) {
  const current = getPath(db, p.source, p.site, now);
  if (current.state === "paused") return;
  save(
    db,
    { ...current, state: "slowed", until: Math.max(until, current.until ?? 0), reason },
    now,
  );
}

export function pathDelivered(db: Database, p: Path, now: number) {
  const current = getPath(db, p.source, p.site, now);
  if (current.state === "open" && current.pauses > 0) save(db, { ...current, pauses: 0 }, now);
}
