import type { Database } from "bun:sqlite";
import { appendEvent } from "./events.ts";
import type { Outcome } from "./outcome.ts";
import { backoff, type RetryPolicy } from "./retry.ts";

export type JobState = "ready" | "leased" | "unknown" | "done" | "dead";

const SOURCE = "queue";

export interface NewMessage {
  id?: string;
  type: string;
  payload: unknown;
  metadata?: Record<string, unknown>;
  priority?: number;
  runAfter?: number;
}

export function enqueue(db: Database, m: NewMessage, now: number): string {
  const id = m.id ?? Bun.randomUUIDv7();
  db.query<unknown, [string, string, string, string, number]>(
    "INSERT INTO messages (id, type, payload, metadata, created_at) VALUES (?, ?, ?, ?, ?)",
  ).run(id, m.type, JSON.stringify(m.payload), JSON.stringify(m.metadata ?? {}), now);
  db.query<unknown, [string, number, number, number]>(
    `INSERT INTO jobs (message_id, state, priority, run_after, updated_at)
     VALUES (?, 'ready', ?, ?, ?)`,
  ).run(id, m.priority ?? 0, m.runAfter ?? now, now);
  appendEvent(db, { messageId: id, kind: "queued", source: SOURCE, at: now });
  return id;
}

export interface ClaimedJob {
  id: string;
  type: string;
  payload: unknown;
  metadata: Record<string, unknown>;
  createdAt: number;
  attempt: number;
}

export function claim(db: Database, now: number, limit: number, leaseMs: number): ClaimedJob[] {
  if (limit <= 0) return [];
  const leased = db
    .query<{ message_id: string; attempt: number }, [number, number, number, number]>(
      `UPDATE jobs SET state = 'leased', attempt = attempt + 1, lease_until = ?, updated_at = ?
       WHERE message_id IN (
         SELECT message_id FROM jobs
         WHERE state = 'ready' AND run_after <= ?
         ORDER BY priority, run_after
         LIMIT ?
       )
       RETURNING message_id, attempt`,
    )
    .all(now + leaseMs, now, now, limit);
  if (leased.length === 0) return [];

  const attempts = new Map(leased.map((r) => [r.message_id, r.attempt]));
  return db
    .query<
      { id: string; type: string; payload: string; metadata: string; created_at: number },
      [string]
    >(
      `SELECT id, type, payload, metadata, created_at FROM messages
       WHERE id IN (SELECT value FROM json_each(?))`,
    )
    .all(JSON.stringify([...attempts.keys()]))
    .map((m) => ({
      id: m.id,
      type: m.type,
      payload: JSON.parse(m.payload),
      metadata: JSON.parse(m.metadata),
      createdAt: m.created_at,
      attempt: attempts.get(m.id) ?? 0,
    }));
}

export interface SettleOptions {
  retry: RetryPolicy;
  reconcileMs: number;
  random?: () => number;
}

export type Settled = "done" | "dead" | "retry" | "unknown" | "stale";

export function settle(
  db: Database,
  job: Pick<ClaimedJob, "id" | "attempt" | "createdAt">,
  outcome: Outcome,
  now: number,
  opts: SettleOptions,
): Settled {
  const guard = "WHERE message_id = ? AND attempt = ? AND state IN ('leased', 'unknown')";
  const event = (kind: string, data?: Record<string, unknown>) =>
    appendEvent(db, {
      messageId: job.id,
      kind,
      source: SOURCE,
      at: now,
      data: { attempt: job.attempt, ...data },
    });

  switch (outcome.kind) {
    case "continue":
    case "done": {
      const r = db
        .query<unknown, [number, string, number]>(
          `UPDATE jobs SET state = 'done', lease_until = NULL, check_after = NULL,
             last_error = NULL, updated_at = ? ${guard}`,
        )
        .run(now, job.id, job.attempt);
      if (r.changes === 0) return "stale";
      event("done");
      return "done";
    }
    case "fail":
      return toDead(db, job, now, `${outcome.code}: ${outcome.reason}`, guard, () =>
        event("dead", { code: outcome.code, reason: outcome.reason }),
      );
    case "defer": {
      const { retry } = opts;
      if (job.attempt >= retry.maxAttempts || now - job.createdAt >= retry.maxAgeMs) {
        const why = `retries exhausted after ${job.attempt} attempts: ${outcome.reason}`;
        return toDead(db, job, now, why, guard, () =>
          event("dead", { code: "retries_exhausted", reason: outcome.reason }),
        );
      }
      const delay = outcome.delayMs ?? backoff(retry, job.attempt, opts.random);
      const r = db
        .query<unknown, [number, string, number, string, number]>(
          `UPDATE jobs SET state = 'ready', run_after = ?, last_error = ?, lease_until = NULL,
             check_after = NULL, updated_at = ? ${guard}`,
        )
        .run(now + delay, outcome.reason, now, job.id, job.attempt);
      if (r.changes === 0) return "stale";
      event("deferred", { reason: outcome.reason, delay_ms: delay });
      return "retry";
    }
    case "unknown": {
      const r = db
        .query<unknown, [number, string, number, string, number]>(
          `UPDATE jobs SET state = 'unknown', check_after = ?, last_error = ?, lease_until = NULL,
             updated_at = ? WHERE message_id = ? AND attempt = ? AND state = 'leased'`,
        )
        .run(now + opts.reconcileMs, outcome.reason, now, job.id, job.attempt);
      if (r.changes === 0) return "stale";
      event("unknown", { reason: outcome.reason });
      return "unknown";
    }
  }
}

function toDead(
  db: Database,
  job: Pick<ClaimedJob, "id" | "attempt">,
  now: number,
  why: string,
  guard: string,
  record: () => void,
): Settled {
  const r = db
    .query<unknown, [string, number, string, number]>(
      `UPDATE jobs SET state = 'dead', last_error = ?, lease_until = NULL, check_after = NULL,
         updated_at = ? ${guard}`,
    )
    .run(why, now, job.id, job.attempt);
  if (r.changes === 0) return "stale";
  record();
  return "dead";
}

export function expireLeases(db: Database, now: number, reconcileMs: number): number {
  return markLeasesUnknown(db, now, now, reconcileMs, "lease expired");
}

export function recoverAfterCrash(db: Database, now: number, reconcileMs: number): number {
  return markLeasesUnknown(db, Number.MAX_SAFE_INTEGER, now, reconcileMs, "process restarted");
}

function markLeasesUnknown(
  db: Database,
  cutoff: number,
  now: number,
  reconcileMs: number,
  reason: string,
): number {
  const rows = db
    .query<{ message_id: string; attempt: number }, [number, string, number, number]>(
      `UPDATE jobs SET state = 'unknown', check_after = ?1, last_error = ?2, lease_until = NULL,
         updated_at = ?3
       WHERE state = 'leased' AND lease_until <= ?4
       RETURNING message_id, attempt`,
    )
    .all(now + reconcileMs, reason, now, cutoff);
  for (const r of rows) {
    appendEvent(db, {
      messageId: r.message_id,
      kind: "unknown",
      source: SOURCE,
      at: now,
      data: { attempt: r.attempt, reason },
    });
  }
  return rows.length;
}

export function resendUnresolved(db: Database, now: number): number {
  const rows = db
    .query<{ message_id: string; attempt: number }, [number, number]>(
      `UPDATE jobs SET state = 'ready', run_after = ?1, check_after = NULL, updated_at = ?1
       WHERE state = 'unknown' AND check_after <= ?2
       RETURNING message_id, attempt`,
    )
    .all(now, now);
  for (const r of rows) {
    appendEvent(db, {
      messageId: r.message_id,
      kind: "duplicate_risk",
      source: SOURCE,
      at: now,
      data: { attempt: r.attempt },
    });
  }
  return rows.length;
}

export function nextWakeAt(db: Database): number | undefined {
  const r = db
    .query<{ t: number | null }, []>(
      `SELECT min(t) AS t FROM (
         SELECT min(run_after)   AS t FROM jobs WHERE state = 'ready'
         UNION ALL SELECT min(lease_until) FROM jobs WHERE state = 'leased'
         UNION ALL SELECT min(check_after) FROM jobs WHERE state = 'unknown'
       )`,
    )
    .get();
  return r?.t ?? undefined;
}

export function countByState(db: Database): Record<JobState, number> {
  const counts: Record<JobState, number> = { ready: 0, leased: 0, unknown: 0, done: 0, dead: 0 };
  for (const r of db
    .query<{ state: JobState; n: number }, []>(
      "SELECT state, count(*) AS n FROM jobs GROUP BY state",
    )
    .all()) {
    counts[r.state] = r.n;
  }
  return counts;
}

export function pendingCount(db: Database): number {
  const r = db
    .query<{ n: number }, []>(
      `SELECT (SELECT count(*) FROM jobs WHERE state = 'ready')
            + (SELECT count(*) FROM jobs WHERE state = 'leased')
            + (SELECT count(*) FROM jobs WHERE state = 'unknown') AS n`,
    )
    .get();
  return r?.n ?? 0;
}
