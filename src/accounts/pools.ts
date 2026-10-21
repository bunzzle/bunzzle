import type { Database } from "bun:sqlite";
import { forgetKeys } from "./api-keys.ts";
import type { ProjectId } from "./projects.ts";

export const SHARED_POOLS = ["main", "bulk"];

export function poolOwner(db: Database, pool: string): ProjectId | null {
  return (
    (db
      .query<{ project_id: string }, [string]>("SELECT project_id FROM pool_owners WHERE pool = ?")
      .get(pool)?.project_id as ProjectId | undefined) ?? null
  );
}

export function poolUsableBy(db: Database, pool: string, project: ProjectId): boolean {
  const owner = poolOwner(db, pool);
  return owner === null || owner === project;
}

export function listPoolOwners(db: Database): Map<string, ProjectId> {
  return new Map(
    db
      .query<{ pool: string; project_id: string }, []>("SELECT pool, project_id FROM pool_owners")
      .all()
      .map((r) => [r.pool, r.project_id as ProjectId]),
  );
}

export function ownPool(
  db: Database,
  pool: string,
  project: ProjectId,
  now: number,
): { cleared: number } {
  db.query<unknown, [string, string, number]>(
    `INSERT INTO pool_owners (pool, project_id, created_at) VALUES (?, ?, ?)
     ON CONFLICT (pool) DO UPDATE SET project_id = excluded.project_id, created_at = excluded.created_at`,
  ).run(pool, project, now);
  let cleared = 0;
  for (const sql of [
    "UPDATE domains SET pool = NULL WHERE pool = ?1 AND project_id <> ?2",
    "UPDATE api_keys SET pool = NULL WHERE pool = ?1 AND project_id IS NOT ?2",
    "UPDATE projects SET pool = NULL WHERE pool = ?1 AND id <> ?2",
  ]) {
    cleared += db.query<unknown, [string, string]>(sql).run(pool, project).changes;
  }
  forgetKeys(db);
  return { cleared };
}

export function sharePool(db: Database, pool: string): boolean {
  return (
    db.query<unknown, [string]>("DELETE FROM pool_owners WHERE pool = ?").run(pool).changes > 0
  );
}
