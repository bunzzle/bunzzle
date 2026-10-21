import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import { appendEvent } from "../core/events.ts";

export interface Suspension {
  target: string;
  reason: string;
  until: number | null;
  createdAt: number;
}

export const SUSPENDED_PREFIX = "waiting: suspended by an operator";

export function suspend(
  db: Database,
  target: string,
  reason: string,
  until: number | null,
  now: number,
): Suspension {
  db.query<unknown, [string, string, number | null, number]>(
    `INSERT INTO suspensions (target, reason, until, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT (target) DO UPDATE SET reason = excluded.reason, until = excluded.until`,
  ).run(target, reason, until, now);
  return activeSuspensions(db, now).find((s) => s.target === target) as Suspension;
}

export function resume(
  db: Database,
  target: string,
  now: number,
): { resumed: boolean; woken: number } {
  const resumed =
    db.query<unknown, [string]>("DELETE FROM suspensions WHERE target = ?").run(target).changes > 0;
  return { resumed, woken: resumed ? wakeSuspended(db, now) : 0 };
}

export function wakeSuspended(db: Database, now: number): number {
  return db
    .query<unknown, [number, number, number, string]>(
      `UPDATE jobs SET run_after = ?, updated_at = ?
       WHERE state = 'ready' AND run_after > ?
         AND id IN (SELECT job_id FROM recipients WHERE reply LIKE ? || '%')`,
    )
    .run(now, now, now, SUSPENDED_PREFIX).changes;
}

export function expireSuspensions(db: Database, now: number): number {
  const gone = db
    .query<unknown, [number]>("DELETE FROM suspensions WHERE until IS NOT NULL AND until <= ?")
    .run(now).changes;
  return gone > 0 ? wakeSuspended(db, now) : 0;
}

export function activeSuspensions(db: Database, now: number): Suspension[] {
  return db
    .query<{ target: string; reason: string; until: number | null; created_at: number }, [number]>(
      "SELECT * FROM suspensions WHERE until IS NULL OR until > ? ORDER BY created_at",
    )
    .all(now)
    .map((r) => ({ target: r.target, reason: r.reason, until: r.until, createdAt: r.created_at }));
}

export function suspensionFor(
  db: Database,
  domain: string,
  provider: string | null,
  now: number,
): Suspension | null {
  const targets = [`domain:${domain}`, ...(provider ? [`provider:${provider}`] : [])];
  return activeSuspensions(db, now).find((s) => targets.includes(s.target)) ?? null;
}

export interface QueueRow {
  destination: string;
  waiting: number;
  sending: number;
  retrying: number;
  scheduled: number;
  suspended: number;
  oldest_age_s: number;
}

export function queueSummary(db: Database, project: ProjectId | null, now: number, limit = 100) {
  const rows = db
    .query<
      {
        target: string;
        path: string | null;
        state: string;
        attempt: number;
        run_after: number;
        created_at: number;
        held: number;
      },
      [string, string | null]
    >(
      `SELECT j.target, j.path, j.state, j.attempt, j.run_after, m.created_at,
         EXISTS (SELECT 1 FROM recipients r WHERE r.job_id = j.id AND r.reply LIKE ?1 || '%') AS held
       FROM jobs j JOIN messages m ON m.id = j.message_id
       WHERE j.state IN ('ready', 'leased', 'unknown') AND (?2 IS NULL OR j.project_id = ?2)`,
    )
    .all(SUSPENDED_PREFIX, project);
  const group = (key: (r: (typeof rows)[number]) => string | null) => {
    const out = new Map<string, QueueRow>();
    for (const r of rows) {
      const k = key(r);
      if (k === null) continue;
      let g = out.get(k);
      if (!g) {
        g = {
          destination: k,
          waiting: 0,
          sending: 0,
          retrying: 0,
          scheduled: 0,
          suspended: 0,
          oldest_age_s: 0,
        };
        out.set(k, g);
      }
      if (r.state !== "ready") g.sending++;
      else if (r.held) g.suspended++;
      else if (r.attempt === 0 && r.run_after > now) g.scheduled++;
      else if (r.attempt > 0) g.retrying++;
      else g.waiting++;
      g.oldest_age_s = Math.max(g.oldest_age_s, Math.round((now - r.created_at) / 1000));
    }
    const total = (g: QueueRow) => g.waiting + g.sending + g.retrying + g.scheduled + g.suspended;
    return [...out.values()].sort((a, b) => total(b) - total(a)).slice(0, limit);
  };
  return {
    domains: group((r) => r.target),
    routes: group((r) => (r.path ? (r.path.split("|")[1] ?? null) : null)),
    suspensions: activeSuspensions(db, now),
  };
}

export interface QueueFilter {
  domain?: string;
  senderDomain?: string;
  olderThanMs?: number;
}

export interface Bulk {
  emails: number;
  jobs: number;
  recipients: number;
  skippedSending: number;
}

export function removeQueued(
  db: Database,
  project: ProjectId | null,
  filter: QueueFilter,
  action: "fail" | "cancel",
  reason: string,
  now: number,
  dryRun: boolean,
): Bulk {
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (filter.domain) {
    where.push("j.target = ?");
    args.push(filter.domain);
  }
  if (filter.senderDomain) {
    where.push("lower(json_extract(m.payload, '$.from')) LIKE ?");
    args.push(`%@${filter.senderDomain}`);
  }
  if (filter.olderThanMs !== undefined) {
    where.push("m.created_at <= ?");
    args.push(now - filter.olderThanMs);
  }
  if (where.length === 0) throw new Error("a filter is required");
  if (project !== null) {
    where.push("j.project_id = ?");
    args.push(project);
  }
  const cond = where.join(" AND ");
  const jobs = db
    .query<{ id: string; message_id: string; state: string }, (string | number)[]>(
      `SELECT j.id, j.message_id, j.state FROM jobs j JOIN messages m ON m.id = j.message_id
       WHERE m.type = 'email' AND j.state IN ('ready', 'leased', 'unknown') AND ${cond}`,
    )
    .all(...args);
  const ready = jobs.filter((j) => j.state === "ready");
  const pendingOf = db.query<{ n: number }, [string]>(
    "SELECT count(*) AS n FROM recipients WHERE job_id = ? AND status IN ('queued', 'deferred')",
  );
  const result: Bulk = {
    emails: new Set(ready.map((j) => j.message_id)).size,
    jobs: ready.length,
    recipients: ready.reduce((n, j) => n + (pendingOf.get(j.id)?.n ?? 0), 0),
    skippedSending: jobs.length - ready.length,
  };
  if (dryRun || ready.length === 0) return result;
  const cls = action === "cancel" ? "canceled" : "operator";
  const killJob = db.query<unknown, [string, number, string]>(
    "UPDATE jobs SET state = 'dead', last_error = ?, updated_at = ? WHERE id = ? AND state = 'ready'",
  );
  const killRecipients = db.query<unknown, [string, string, number, string]>(
    `UPDATE recipients SET status = 'failed', class = ?, reply = ?, updated_at = ?
     WHERE job_id = ? AND status IN ('queued', 'deferred')`,
  );
  const live = db.query<{ n: number }, [string]>(
    "SELECT count(*) AS n FROM jobs WHERE message_id = ? AND state IN ('ready', 'leased', 'unknown')",
  );
  const text = `${action === "cancel" ? "canceled" : "failed"} by an operator: ${reason}`;
  const touched = new Set<string>();
  for (const j of ready) {
    killJob.run(`operator: ${reason}`, now, j.id);
    killRecipients.run(cls, text, now, j.id);
    touched.add(j.message_id);
  }
  for (const id of touched) {
    appendEvent(db, {
      messageId: id,
      kind: action === "cancel" ? "canceled" : "dead",
      source: "operator",
      at: now,
      data: action === "cancel" ? { reason } : { code: "operator", reason },
    });
    if (action === "cancel" && (live.get(id)?.n ?? 0) === 0) {
      db.query<unknown, [string]>("DELETE FROM bodies WHERE message_id = ?").run(id);
    }
  }
  return result;
}
