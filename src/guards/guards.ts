import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import type { Logger } from "../core/log.ts";
import { bucketOf, DAY_MS } from "../ips/warmup.ts";

const HOUR_MS = 3_600_000;
const BASELINE_HOURS = 168;

export interface Hold {
  id: string;
  target: string;
  lane: string;
  reason: string;
  createdAt: number;
  releasedAt: number | null;
}

interface HoldRow {
  id: string;
  target: string;
  lane: string;
  reason: string;
  created_at: number;
  released_at: number | null;
}

const fromRow = (r: HoldRow): Hold => ({
  id: r.id,
  target: r.target,
  lane: r.lane,
  reason: r.reason,
  createdAt: r.created_at,
  releasedAt: r.released_at,
});

export function activeHold(db: Database, target: string, lane: string): Hold | null {
  const r = db
    .query<HoldRow, [string, string]>(
      "SELECT * FROM holds WHERE target = ? AND lane = ? AND released_at IS NULL LIMIT 1",
    )
    .get(target, lane);
  return r ? fromRow(r) : null;
}

export function createHold(
  db: Database,
  target: string,
  lane: string,
  reason: string,
  now: number,
): { hold: Hold; created: boolean } {
  const existing = activeHold(db, target, lane);
  if (existing) return { hold: existing, created: false };
  const hold: Hold = {
    id: Bun.randomUUIDv7(),
    target,
    lane,
    reason,
    createdAt: now,
    releasedAt: null,
  };
  db.query<unknown, [string, string, string, string, number]>(
    "INSERT INTO holds (id, target, lane, reason, created_at) VALUES (?, ?, ?, ?, ?)",
  ).run(hold.id, target, lane, reason, now);
  return { hold, created: true };
}

export const PROJECT_HOLDS = `(?1 IS NULL
  OR target IN (SELECT 'domain:' || name FROM domains WHERE project_id = ?1)
  OR target IN (SELECT 'key:' || id FROM api_keys WHERE project_id = ?1))`;

export function releaseHold(
  db: Database,
  project: ProjectId | null,
  id: string,
  now: number,
): boolean {
  return (
    db
      .query<unknown, [string | null, number, string]>(
        `UPDATE holds SET released_at = ?2 WHERE id = ?3 AND released_at IS NULL AND ${PROJECT_HOLDS}`,
      )
      .run(project, now, id).changes > 0
  );
}

export function listHolds(db: Database, project: ProjectId | null, all = false): Hold[] {
  return db
    .query<HoldRow, [string | null]>(
      `SELECT * FROM holds WHERE ${all ? "" : "released_at IS NULL AND "}${PROJECT_HOLDS}
       ORDER BY created_at DESC`,
    )
    .all(project)
    .map(fromRow);
}

export function countSender(
  db: Database,
  domain: string,
  lane: string,
  delta: { delivered?: number; hardBounced?: number; complained?: number },
  now: number,
): void {
  db.query<unknown, [string, string, number, number, number, number]>(
    `INSERT INTO sender_stats (domain, lane, day, delivered, hard_bounced, complained)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (domain, lane, day) DO UPDATE SET delivered = delivered + excluded.delivered,
       hard_bounced = hard_bounced + excluded.hard_bounced,
       complained = complained + excluded.complained`,
  ).run(
    domain,
    lane,
    Math.floor(now / DAY_MS),
    delta.delivered ?? 0,
    delta.hardBounced ?? 0,
    delta.complained ?? 0,
  );
}

export interface SenderRates {
  domain: string;
  lane: string;
  delivered: number;
  hardBounced: number;
  complained: number;
  complaintRate: number;
  bounceRate: number;
}

export function senderRates(db: Database, project: ProjectId | null, now: number): SenderRates[] {
  const since = Math.floor(now / DAY_MS) - 1;
  return db
    .query<
      { domain: string; lane: string; delivered: number; hard_bounced: number; complained: number },
      [number, string | null]
    >(
      `SELECT domain, lane, sum(delivered) AS delivered, sum(hard_bounced) AS hard_bounced,
         sum(complained) AS complained
       FROM sender_stats WHERE day >= ?1
         AND (?2 IS NULL OR domain IN (SELECT name FROM domains WHERE project_id = ?2))
       GROUP BY domain, lane`,
    )
    .all(since, project)
    .map((r) => ({
      domain: r.domain,
      lane: r.lane,
      delivered: r.delivered,
      hardBounced: r.hard_bounced,
      complained: r.complained,
      complaintRate: r.complained / Math.max(1, r.delivered),
      bounceRate: r.hard_bounced / Math.max(1, r.delivered + r.hard_bounced),
    }));
}

export function reputationGuard(db: Database, now: number, minVolume: number, log: Logger): Hold[] {
  const made: Hold[] = [];
  for (const r of senderRates(db, null, now)) {
    if (r.lane !== "bulk" || r.delivered + r.hardBounced < minVolume) continue;
    let reason: string | null = null;
    if (r.complaintRate >= 0.003) {
      reason = `complaint rate ${(r.complaintRate * 100).toFixed(2)}% over the last two days (Gmail's limit is 0.3%)`;
    } else if (r.bounceRate >= 0.05) {
      reason = `hard bounce rate ${(r.bounceRate * 100).toFixed(1)}% over the last two days`;
    } else if (r.complaintRate >= 0.001) {
      log.warn("complaint rate rising for bulk mail", {
        domain: r.domain,
        rate: `${(r.complaintRate * 100).toFixed(2)}%`,
      });
    }
    if (!reason) continue;
    const { hold, created } = createHold(db, `domain:${r.domain}`, "bulk", reason, now);
    if (created) {
      log.error("bulk mail paused for a sending domain", { domain: r.domain, reason });
      made.push(hold);
    }
  }
  return made;
}

export function countKeyBulk(db: Database, keyId: string, n: number, now: number): number {
  const hour = Math.floor(now / HOUR_MS);
  return (
    db
      .query<{ bulk: number }, [string, number, number]>(
        `INSERT INTO key_stats (key_id, hour, bulk) VALUES (?, ?, ?)
         ON CONFLICT (key_id, hour) DO UPDATE SET bulk = bulk + excluded.bulk
         RETURNING bulk`,
      )
      .get(keyId, hour, n)?.bulk ?? n
  );
}

export function anomalyThreshold(db: Database, keyId: string, now: number, floor: number): number {
  const hour = Math.floor(now / HOUR_MS);
  const sum =
    db
      .query<{ n: number | null }, [string, number, number]>(
        "SELECT sum(bulk) AS n FROM key_stats WHERE key_id = ? AND hour >= ? AND hour < ?",
      )
      .get(keyId, hour - BASELINE_HOURS, hour)?.n ?? 0;
  return Math.max(floor, Math.ceil((10 * sum) / BASELINE_HOURS));
}

export interface Attribution {
  domain: string;
  lane: "transactional" | "bulk";
  source: string | null;
  bucket: string;
  apiKeyId: string | null;
}

export function attributionOf(db: Database, messageId: string): Attribution | null {
  const m = db
    .query<{ payload: string; metadata: string }, [string]>(
      "SELECT payload, metadata FROM messages WHERE id = ?",
    )
    .get(messageId);
  if (!m) return null;
  const payload = JSON.parse(m.payload) as { from?: string };
  const meta = JSON.parse(m.metadata) as { lane?: string; apiKeyId?: string | null };
  const path = db
    .query<{ path: string | null }, [string]>(
      "SELECT path FROM jobs WHERE message_id = ? AND path IS NOT NULL LIMIT 1",
    )
    .get(messageId)?.path;
  const [source = null, target = null] = path ? path.split("|") : [];
  return {
    domain: (payload.from ?? "").split("@").pop()?.toLowerCase() ?? "",
    lane: meta.lane === "bulk" ? "bulk" : "transactional",
    source: source && source !== "default" ? source : null,
    bucket: bucketOf(target),
    apiKeyId: meta.apiKeyId ?? null,
  };
}
