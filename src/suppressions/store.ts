import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";

export type SuppressionScope = "all" | "bulk";
export type SuppressionReason =
  | "hard-bounce"
  | "no-domain"
  | "complaint"
  | "unsubscribe"
  | "manual";

export interface Suppression {
  address: string;
  scope: SuppressionScope;
  reason: SuppressionReason;
  detail: string | null;
  sourceMessageId: string | null;
  createdAt: number;
  expiresAt: number | null;
}

const DAY = 86_400_000;

const HARD = new Set([
  "user-unknown",
  "mailbox-disabled",
  "bad-address",
  "mailbox-moved",
  "mailbox-owner-changed",
]);
const NO_DOMAIN = new Set(["null-mx", "bad-domain", "domain-owner-changed"]);

export function suppressionForClass(
  cls: string,
): { reason: SuppressionReason; scope: SuppressionScope; ttlMs: number } | null {
  if (HARD.has(cls)) return { reason: "hard-bounce", scope: "all", ttlMs: 365 * DAY };
  if (NO_DOMAIN.has(cls)) return { reason: "no-domain", scope: "all", ttlMs: 30 * DAY };
  return null;
}

export interface NewSuppression {
  address: string;
  scope: SuppressionScope;
  reason: SuppressionReason;
  detail?: string | null;
  messageId?: string | null;
  ttlMs?: number | null;
}

export function suppress(db: Database, project: ProjectId, s: NewSuppression, now: number): void {
  db.query<
    unknown,
    [string, string, SuppressionScope, string, string | null, string | null, number, number | null]
  >(
    `INSERT INTO suppressions (project_id, address, scope, reason, detail, source_message_id, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (project_id, address, scope) DO UPDATE SET reason = excluded.reason, detail = excluded.detail,
       source_message_id = excluded.source_message_id, created_at = excluded.created_at,
       expires_at = CASE
         WHEN suppressions.expires_at IS NULL AND suppressions.reason IN ('complaint', 'unsubscribe', 'manual')
           THEN NULL
         ELSE excluded.expires_at END`,
  ).run(
    project,
    s.address.toLowerCase(),
    s.scope,
    s.reason,
    s.detail ?? null,
    s.messageId ?? null,
    now,
    s.ttlMs ? now + s.ttlMs : null,
  );
}

interface Row {
  address: string;
  scope: SuppressionScope;
  reason: SuppressionReason;
  detail: string | null;
  source_message_id: string | null;
  created_at: number;
  expires_at: number | null;
}

const fromRow = (r: Row): Suppression => ({
  address: r.address,
  scope: r.scope,
  reason: r.reason,
  detail: r.detail,
  sourceMessageId: r.source_message_id,
  createdAt: r.created_at,
  expiresAt: r.expires_at,
});

export function suppressionFor(
  db: Database,
  project: ProjectId,
  address: string,
  lane: "transactional" | "bulk",
  now: number,
): Suppression | null {
  const r = db
    .query<Row, [string, string, number, string]>(
      `SELECT * FROM suppressions
       WHERE project_id = ? AND address = ? AND (expires_at IS NULL OR expires_at > ?)
         AND (scope = 'all' OR scope = ?)
       ORDER BY scope = 'all' DESC LIMIT 1`,
    )
    .get(project, address.toLowerCase(), now, lane === "bulk" ? "bulk" : "all");
  return r ? fromRow(r) : null;
}

export function listSuppressions(db: Database, project: ProjectId, now: number): Suppression[] {
  return db
    .query<Row, [string, number]>(
      `SELECT * FROM suppressions WHERE project_id = ? AND (expires_at IS NULL OR expires_at > ?)
       ORDER BY created_at DESC`,
    )
    .all(project, now)
    .map(fromRow);
}

export function removeSuppression(
  db: Database,
  project: ProjectId,
  address: string,
  scope: SuppressionScope | null,
): number {
  return scope
    ? db
        .query<unknown, [string, string, string]>(
          "DELETE FROM suppressions WHERE project_id = ? AND address = ? AND scope = ?",
        )
        .run(project, address.toLowerCase(), scope).changes
    : db
        .query<unknown, [string, string]>(
          "DELETE FROM suppressions WHERE project_id = ? AND address = ?",
        )
        .run(project, address.toLowerCase()).changes;
}
