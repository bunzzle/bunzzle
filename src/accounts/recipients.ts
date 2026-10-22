import type { Database } from "bun:sqlite";
import type { ProjectId } from "./projects.ts";

export const RECIPIENT_MEMORY_MS = 90 * 24 * 3_600_000;

const HASH_BYTES = 16;
const SEEDED = "project_recipients_seeded";
const enc = new TextEncoder();

export type RecipientHash = (address: string) => Promise<Uint8Array>;

export async function recipientHasher(key: Uint8Array): Promise<RecipientHash> {
  const k = await crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return async (address) =>
    new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(address.toLowerCase()))).slice(
      0,
      HASH_BYTES,
    );
}

export function newRecipients(
  db: Database,
  project: ProjectId,
  hashes: Uint8Array[],
  now: number,
): number {
  const known = db.query<{ n: number }, [string, Uint8Array, number]>(
    "SELECT 1 AS n FROM project_recipients WHERE project_id = ? AND address_hash = ? AND last_at > ?",
  );
  const seen = new Set<string>();
  let fresh = 0;
  for (const h of hashes) {
    const hex = h.toHex();
    if (seen.has(hex)) continue;
    seen.add(hex);
    if (!known.get(project, h, now - RECIPIENT_MEMORY_MS)) fresh++;
  }
  return fresh;
}

export function rememberRecipients(
  db: Database,
  project: ProjectId,
  hashes: Uint8Array[],
  now: number,
): void {
  const put = db.query<unknown, [string, Uint8Array, number]>(
    `INSERT INTO project_recipients (project_id, address_hash, last_at) VALUES (?, ?, ?)
     ON CONFLICT (project_id, address_hash) DO UPDATE SET last_at = max(last_at, excluded.last_at)`,
  );
  for (const h of hashes) put.run(project, h, now);
}

export function pruneRecipients(db: Database, now: number): void {
  db.query<unknown, [number]>("DELETE FROM project_recipients WHERE last_at <= ?").run(
    now - RECIPIENT_MEMORY_MS,
  );
}

export function recipientsSeeded(db: Database): boolean {
  return (
    db
      .query<{ value: string }, [string]>("SELECT value FROM settings WHERE key = ?")
      .get(SEEDED) !== null
  );
}

interface SeedRow {
  rowid: number;
  project_id: string;
  address: string;
  created_at: number;
}

export function seedPage(
  db: Database,
  after: number,
  now: number,
  limit = 1_000,
): { rows: { project: ProjectId; address: string; at: number }[]; next: number | null } {
  const rows = db
    .query<SeedRow, [number, number, number]>(
      `SELECT r.rowid, m.project_id, r.address, m.created_at FROM recipients r
       JOIN jobs j ON j.id = r.job_id JOIN messages m ON m.id = j.message_id
       WHERE r.rowid > ? AND m.created_at > ? AND r.class IS NOT 'suppressed'
         AND json_extract(m.metadata, '$.test') IS NOT 1
       ORDER BY r.rowid LIMIT ?`,
    )
    .all(after, now - RECIPIENT_MEMORY_MS, limit);
  return {
    rows: rows.map((r) => ({
      project: r.project_id as ProjectId,
      address: r.address,
      at: r.created_at,
    })),
    next: rows.length === limit ? (rows.at(-1)?.rowid ?? null) : null,
  };
}

export function finishSeed(db: Database, now: number): void {
  db.query<unknown, [string, string, number]>(
    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO NOTHING",
  ).run(SEEDED, String(now), now);
}
