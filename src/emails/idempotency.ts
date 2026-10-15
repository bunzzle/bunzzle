import type { Database } from "bun:sqlite";

export const IDEMPOTENCY_TTL_MS = 24 * 3_600_000;

export interface IdempotencyRecord {
  bodyHash: string;
  messageId: string;
  createdAt: number;
}

export function findIdempotent(
  db: Database,
  apiKeyId: string,
  key: string,
  now: number,
): IdempotencyRecord | null {
  const r = db
    .query<{ body_hash: string; message_id: string; created_at: number }, [string, string, number]>(
      `SELECT body_hash, message_id, created_at FROM idempotency
       WHERE api_key_id = ? AND key = ? AND created_at > ?`,
    )
    .get(apiKeyId, key, now - IDEMPOTENCY_TTL_MS);
  return r ? { bodyHash: r.body_hash, messageId: r.message_id, createdAt: r.created_at } : null;
}

export function rememberIdempotent(
  db: Database,
  apiKeyId: string,
  key: string,
  bodyHash: string,
  messageId: string,
  now: number,
): void {
  db.query<unknown, [string, string, string, string, number]>(
    `INSERT INTO idempotency (api_key_id, key, body_hash, message_id, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (api_key_id, key) DO UPDATE SET body_hash = excluded.body_hash,
       message_id = excluded.message_id, created_at = excluded.created_at`,
  ).run(apiKeyId, key, bodyHash, messageId, now);
}

export function pruneIdempotency(db: Database, now: number): number {
  return db
    .query<unknown, [number]>("DELETE FROM idempotency WHERE created_at <= ?")
    .run(now - IDEMPOTENCY_TTL_MS).changes;
}
