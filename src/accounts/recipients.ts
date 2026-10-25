import type { Database } from "bun:sqlite";
import type { ProjectId } from "./projects.ts";

export const RECIPIENT_MEMORY_MS = 90 * 24 * 3_600_000;

const HASH_BYTES = 16;
const REFRESH_MS = 24 * 3_600_000;
const SEEDED = "project_recipients_seeded";

export type RecipientHash = (address: string) => Uint8Array;

export function recipientHasher(key: Uint8Array): RecipientHash {
  const keyed = new Bun.CryptoHasher("sha256", key);
  const out = new Uint8Array(64);
  return (address) => {
    keyed.copy().update(address.toLowerCase()).digest(out);
    return out.slice(0, HASH_BYTES);
  };
}

export interface RecipientCheck {
  fresh: number;
  stale: Uint8Array[];
}

export function checkRecipients(
  db: Database,
  project: ProjectId,
  hashes: Uint8Array[],
  now: number,
): RecipientCheck {
  const last = db.query<{ last_at: number }, [string, Uint8Array]>(
    "SELECT last_at FROM project_recipients WHERE project_id = ? AND address_hash = ?",
  );
  const seen = new Set<string>();
  const stale: Uint8Array[] = [];
  let fresh = 0;
  for (const h of hashes) {
    const hex = h.toHex();
    if (seen.has(hex)) continue;
    seen.add(hex);
    const at = last.get(project, h)?.last_at;
    if (at === undefined || at <= now - RECIPIENT_MEMORY_MS) fresh++;
    if (at === undefined || at <= now - REFRESH_MS) stale.push(h);
  }
  return { fresh, stale };
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
