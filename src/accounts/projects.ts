import type { Database } from "bun:sqlite";
import { forgetKeys } from "./api-keys.ts";

declare const brand: unique symbol;

export type ProjectId = string & { readonly [brand]: "ProjectId" };

export const DEFAULT_PROJECT = "default" as ProjectId;

export const PROJECT_NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/;

export interface Project {
  id: ProjectId;
  name: string;
  perHour: number | null;
  perDay: number | null;
  pool: string | null;
  createdAt: number;
  suspendedAt: number | null;
  deletedAt: number | null;
}

interface Row {
  id: string;
  name: string;
  per_hour: number | null;
  per_day: number | null;
  pool: string | null;
  created_at: number;
  suspended_at: number | null;
  deleted_at: number | null;
}

const fromRow = (r: Row): Project => ({
  id: r.id as ProjectId,
  name: r.name,
  perHour: r.per_hour,
  perDay: r.per_day,
  pool: r.pool,
  createdAt: r.created_at,
  suspendedAt: r.suspended_at,
  deletedAt: r.deleted_at,
});

export function projectOfMessage(db: Database, messageId: string): ProjectId | null {
  return (
    (db
      .query<{ project_id: string }, [string]>("SELECT project_id FROM messages WHERE id = ?")
      .get(messageId)?.project_id as ProjectId | undefined) ?? null
  );
}

export function createProject(db: Database, name: string, now: number): Project | null {
  const id = Bun.randomUUIDv7();
  const added = db
    .query<unknown, [string, string, number]>(
      "INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
    )
    .run(id, name, now).changes;
  return added ? findProject(db, id) : null;
}

export function findProject(db: Database, idOrName: string): Project | null {
  const r = db
    .query<Row, [string]>(
      "SELECT * FROM projects WHERE (id = ?1 OR name = ?1) AND deleted_at IS NULL",
    )
    .get(idOrName);
  return r ? fromRow(r) : null;
}

export function findRemovedProject(db: Database, idOrName: string): Project | null {
  const r = db
    .query<Row, [string]>(
      "SELECT * FROM projects WHERE (id = ?1 OR name = ?1) AND deleted_at IS NOT NULL",
    )
    .get(idOrName);
  return r ? fromRow(r) : null;
}

export function listProjects(db: Database): Project[] {
  return db
    .query<Row, []>("SELECT * FROM projects WHERE deleted_at IS NULL ORDER BY name")
    .all()
    .map(fromRow);
}

export function liveProjects(db: Database): number {
  return (
    db.query<{ n: number }, []>("SELECT count(*) AS n FROM projects WHERE deleted_at IS NULL").get()
      ?.n ?? 0
  );
}

export interface ProjectChange {
  name?: string;
  perHour?: number | null;
  perDay?: number | null;
  pool?: string | null;
  suspended?: boolean;
}

export function updateProject(
  db: Database,
  id: ProjectId,
  c: ProjectChange,
  now: number,
): Project | null {
  const p = findProject(db, id);
  if (!p) return null;
  const suspendedAt =
    c.suspended === undefined ? p.suspendedAt : c.suspended ? (p.suspendedAt ?? now) : null;
  db.query<unknown, [string, number | null, number | null, string | null, number | null, string]>(
    `UPDATE projects SET name = ?, per_hour = ?, per_day = ?, pool = ?, suspended_at = ?
     WHERE id = ? AND deleted_at IS NULL`,
  ).run(
    c.name ?? p.name,
    c.perHour === undefined ? p.perHour : c.perHour,
    c.perDay === undefined ? p.perDay : c.perDay,
    c.pool === undefined ? p.pool : c.pool,
    suspendedAt,
    id,
  );
  return findProject(db, id);
}

export function nameTaken(db: Database, name: string, except: ProjectId | null): boolean {
  return (
    db
      .query<{ n: number }, [string, string | null]>(
        "SELECT 1 AS n FROM projects WHERE name = ? AND (?2 IS NULL OR id <> ?2)",
      )
      .get(name, except) !== null
  );
}

export function deleteProject(db: Database, id: ProjectId, now: number): boolean {
  const done =
    db
      .query<unknown, [number, string]>(
        "UPDATE projects SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
      )
      .run(now, id).changes > 0;
  if (done) {
    db.query<unknown, [number, string]>(
      "UPDATE api_keys SET revoked_at = ? WHERE project_id = ? AND revoked_at IS NULL",
    ).run(now, id);
    forgetKeys(db);
  }
  return done;
}

export function recordAdminEvent(
  db: Database,
  e: { kind: string; project: ProjectId; actor: string; data?: Record<string, unknown> },
  now: number,
): void {
  db.query<unknown, [string, string, string, string | null, number]>(
    "INSERT INTO admin_events (kind, project_id, actor, data, occurred_at) VALUES (?, ?, ?, ?, ?)",
  ).run(e.kind, e.project, e.actor, e.data ? JSON.stringify(e.data) : null, now);
}
