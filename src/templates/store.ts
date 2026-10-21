import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";

export interface Content {
  subject: string;
  html: string | null;
  text: string | null;
}

export interface TemplateInfo {
  id: string;
  name: string;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface TemplateVersion extends Content {
  version: number;
  createdAt: number;
}

interface InfoRow {
  id: string;
  name: string;
  version: number;
  created_at: number;
  updated_at: number;
}

interface VersionRow {
  version: number;
  subject: string;
  html: string | null;
  text: string | null;
  created_at: number;
}

const info = (r: InfoRow): TemplateInfo => ({
  id: r.id,
  name: r.name,
  version: r.version,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

const version = (r: VersionRow): TemplateVersion => ({
  version: r.version,
  subject: r.subject,
  html: r.html,
  text: r.text,
  createdAt: r.created_at,
});

const COLUMNS = "id, name, version, created_at, updated_at";

function insertVersion(db: Database, id: string, v: number, c: Content, now: number) {
  db.query<unknown, [string, number, string, string | null, string | null, number]>(
    `INSERT INTO template_versions (template_id, version, subject, html, text, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, v, c.subject, c.html, c.text, now);
}

export function createTemplate(
  db: Database,
  project: ProjectId,
  name: string,
  content: Content,
  now: number,
): TemplateInfo | null {
  const id = Bun.randomUUIDv7();
  const added = db
    .query<unknown, [string, string, string, number, number]>(
      `INSERT INTO templates (id, project_id, name, version, created_at, updated_at)
       VALUES (?, ?, ?, 1, ?, ?) ON CONFLICT DO NOTHING`,
    )
    .run(id, project, name, now, now).changes;
  if (!added) return null;
  insertVersion(db, id, 1, content, now);
  return { id, name, version: 1, createdAt: now, updatedAt: now };
}

export function findTemplate(
  db: Database,
  project: ProjectId,
  idOrName: string,
): TemplateInfo | null {
  const row = db
    .query<InfoRow, [string, string]>(
      `SELECT ${COLUMNS} FROM templates
       WHERE project_id = ?1 AND (id = ?2 OR name = ?2) AND deleted_at IS NULL`,
    )
    .get(project, idOrName);
  return row ? info(row) : null;
}

export function listTemplates(db: Database, project: ProjectId): TemplateInfo[] {
  return db
    .query<InfoRow, [string]>(
      `SELECT ${COLUMNS} FROM templates WHERE project_id = ? AND deleted_at IS NULL ORDER BY name`,
    )
    .all(project)
    .map(info);
}

export function getVersion(db: Database, id: string, v: number): TemplateVersion | null {
  const row = db
    .query<VersionRow, [string, number]>(
      `SELECT version, subject, html, text, created_at FROM template_versions
       WHERE template_id = ? AND version = ?`,
    )
    .get(id, v);
  return row ? version(row) : null;
}

export function listVersions(db: Database, id: string): number[] {
  return db
    .query<{ version: number }, [string]>(
      "SELECT version FROM template_versions WHERE template_id = ? ORDER BY version",
    )
    .all(id)
    .map((r) => r.version);
}

export function addVersion(
  db: Database,
  project: ProjectId,
  id: string,
  content: Content,
  now: number,
): number | null {
  const row = db
    .query<{ version: number }, [number, string, string]>(
      `UPDATE templates SET version = version + 1, updated_at = ?
       WHERE id = ? AND project_id = ? AND deleted_at IS NULL RETURNING version`,
    )
    .get(now, id, project);
  if (!row) return null;
  insertVersion(db, id, row.version, content, now);
  return row.version;
}

export function deleteTemplate(db: Database, project: ProjectId, id: string, now: number): boolean {
  return (
    db
      .query<unknown, [number, string, string]>(
        "UPDATE templates SET deleted_at = ? WHERE id = ? AND project_id = ? AND deleted_at IS NULL",
      )
      .run(now, id, project).changes > 0
  );
}
