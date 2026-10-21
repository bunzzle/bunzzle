import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";

export type SuppressionScope = "all" | "bulk";
export type SuppressionReason =
  | "hard-bounce"
  | "no-domain"
  | "complaint"
  | "unsubscribe"
  | "manual"
  | "invalid";

const SHARED_REASONS = "('hard-bounce', 'no-domain')";

const shared = (s: Suppression): Suppression => ({
  ...s,
  reason: "invalid",
  detail: null,
  sourceMessageId: null,
});

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
  sharedBounces = false,
): Suppression | null {
  const r = db
    .query<Row & { project_id: string }, [string, string, number, string, number]>(
      `SELECT * FROM suppressions
       WHERE address = ?2 AND (expires_at IS NULL OR expires_at > ?3)
         AND (scope = 'all' OR scope = ?4)
         AND (project_id = ?1 OR (?5 AND reason IN ${SHARED_REASONS}))
       ORDER BY project_id = ?1 DESC, scope = 'all' DESC LIMIT 1`,
    )
    .get(
      project,
      address.toLowerCase(),
      now,
      lane === "bulk" ? "bulk" : "all",
      sharedBounces ? 1 : 0,
    );
  if (!r) return null;
  return r.project_id === project ? fromRow(r) : shared(fromRow(r));
}

export function listSuppressions(
  db: Database,
  project: ProjectId,
  now: number,
  sharedBounces = false,
): Suppression[] {
  const own = db
    .query<Row, [string, number]>(
      `SELECT * FROM suppressions WHERE project_id = ? AND (expires_at IS NULL OR expires_at > ?)
       ORDER BY created_at DESC`,
    )
    .all(project, now)
    .map(fromRow);
  if (!sharedBounces) return own;
  const others = db
    .query<Row, [string, number]>(
      `SELECT address, scope, min(reason) AS reason, NULL AS detail, NULL AS source_message_id,
         min(created_at) AS created_at, max(expires_at) AS expires_at
       FROM suppressions
       WHERE project_id <> ?1 AND reason IN ${SHARED_REASONS}
         AND (expires_at IS NULL OR expires_at > ?2)
         AND address NOT IN (SELECT address FROM suppressions WHERE project_id = ?1)
       GROUP BY address, scope`,
    )
    .all(project, now)
    .map((r) => shared(fromRow(r)));
  return [...own, ...others].sort((a, b) => b.createdAt - a.createdAt);
}

export function sharedSuppression(
  db: Database,
  project: ProjectId,
  address: string,
  now: number,
): boolean {
  return (
    db
      .query<{ n: number }, [string, string, number]>(
        `SELECT 1 AS n FROM suppressions
         WHERE address = ?2 AND project_id <> ?1 AND reason IN ${SHARED_REASONS}
           AND (expires_at IS NULL OR expires_at > ?3) LIMIT 1`,
      )
      .get(project, address.toLowerCase(), now) !== null
  );
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
