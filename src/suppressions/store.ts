import type { Database } from "bun:sqlite";

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

export function suppress(db: Database, s: NewSuppression, now: number): void {
  db.query<
    unknown,
    [string, SuppressionScope, string, string | null, string | null, number, number | null]
  >(
    `INSERT INTO suppressions (address, scope, reason, detail, source_message_id, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (address, scope) DO UPDATE SET reason = excluded.reason, detail = excluded.detail,
       source_message_id = excluded.source_message_id, created_at = excluded.created_at,
       expires_at = CASE
         WHEN suppressions.expires_at IS NULL AND suppressions.reason IN ('complaint', 'unsubscribe', 'manual')
           THEN NULL
         ELSE excluded.expires_at END`,
  ).run(
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
  address: string,
  lane: "transactional" | "bulk",
  now: number,
): Suppression | null {
  const r = db
    .query<Row, [string, number, string]>(
      `SELECT * FROM suppressions
       WHERE address = ? AND (expires_at IS NULL OR expires_at > ?)
         AND (scope = 'all' OR scope = ?)
       ORDER BY scope = 'all' DESC LIMIT 1`,
    )
    .get(address.toLowerCase(), now, lane === "bulk" ? "bulk" : "all");
  return r ? fromRow(r) : null;
}

export function listSuppressions(db: Database, now: number): Suppression[] {
  return db
    .query<Row, [number]>(
      "SELECT * FROM suppressions WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC",
    )
    .all(now)
    .map(fromRow);
}

export function removeSuppression(
  db: Database,
  address: string,
  scope: SuppressionScope | null,
): number {
  return scope
    ? db
        .query<unknown, [string, string]>(
          "DELETE FROM suppressions WHERE address = ? AND scope = ?",
        )
        .run(address.toLowerCase(), scope).changes
    : db
        .query<unknown, [string]>("DELETE FROM suppressions WHERE address = ?")
        .run(address.toLowerCase()).changes;
}
