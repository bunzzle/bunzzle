import type { Database } from "bun:sqlite";
import { poolUsableBy } from "./pools.ts";
import type { ProjectId } from "./projects.ts";

export const RELAY_TARGET = "relay";

export interface PoolRule {
  id: string;
  project: ProjectId | null;
  match: string;
  target: string;
  createdAt: number;
}

interface Row {
  id: string;
  project_id: string | null;
  match: string;
  target: string;
  created_at: number;
}

const fromRow = (r: Row): PoolRule => ({
  id: r.id,
  project: r.project_id as ProjectId | null,
  match: r.match,
  target: r.target,
  createdAt: r.created_at,
});

export function createPoolRule(
  db: Database,
  project: ProjectId | null,
  match: string,
  target: string,
  now: number,
): PoolRule | null {
  const id = Bun.randomUUIDv7();
  const done = db
    .query<unknown, [string, string | null, string, string, number]>(
      `INSERT INTO pool_rules (id, project_id, match, target, created_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT DO NOTHING`,
    )
    .run(id, project, match, target, now).changes;
  return done ? { id, project, match, target, createdAt: now } : null;
}

export function listPoolRules(db: Database, project: ProjectId | null): PoolRule[] {
  return db
    .query<Row, [string | null]>("SELECT * FROM pool_rules WHERE project_id IS ? ORDER BY match")
    .all(project)
    .map(fromRow);
}

export function deletePoolRule(db: Database, project: ProjectId | null, id: string): boolean {
  return (
    db
      .query<unknown, [string, string | null]>(
        "DELETE FROM pool_rules WHERE id = ? AND project_id IS ?",
      )
      .run(id, project).changes > 0
  );
}

export type PoolChoice = (
  | { pool: string | null; rule: string | null }
  | { relay: true; rule: string }
) & { skipped: string[] };

export function choosePool(
  db: Database,
  job: { project: ProjectId; domain: string; provider: string | null; senderPool: string | null },
  known: (pool: string) => boolean,
): PoolChoice {
  const rows = db
    .query<Row, [string, string, string]>(
      `SELECT * FROM pool_rules WHERE (project_id = ?1 OR project_id IS NULL)
       AND match IN (?2, ?3)`,
    )
    .all(job.project, job.domain, job.provider ?? job.domain);
  const skipped: string[] = [];
  const pick = (server: boolean): Row | null => {
    const level = rows.filter((r) => (r.project_id === null) === server);
    for (const match of [job.domain, job.provider]) {
      const r = level.find((x) => x.match === match);
      if (!r) continue;
      if (server && r.target === RELAY_TARGET) return r;
      if (known(r.target) && poolUsableBy(db, r.target, job.project)) return r;
      skipped.push(r.id);
    }
    return null;
  };
  const own = pick(false);
  if (own) return { pool: own.target, rule: own.id, skipped };
  if (job.senderPool !== null) return { pool: job.senderPool, rule: null, skipped };
  const server = pick(true);
  if (server?.target === RELAY_TARGET) return { relay: true, rule: server.id, skipped };
  if (server) return { pool: server.target, rule: server.id, skipped };
  return { pool: null, rule: null, skipped };
}
