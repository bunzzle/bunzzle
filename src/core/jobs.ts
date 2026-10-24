import type { Database } from "bun:sqlite";
import { appendEvent } from "./events.ts";
import type { Outcome, Settled } from "./outcome.ts";
import { type RetryPolicy, retryDelay } from "./retry.ts";

export type { Settled } from "./outcome.ts";

export type JobState = "ready" | "leased" | "unknown" | "done" | "dead";

const SOURCE = "queue";

const PAUSED_PROJECTS =
  "SELECT id FROM projects WHERE suspended_at IS NOT NULL OR deleted_at IS NOT NULL";

const SENDABLE = (now: string) =>
  `(project_id NOT IN (${PAUSED_PROJECTS}) OR (expires_at IS NOT NULL AND expires_at <= ${now}))`;

export interface NewMessage {
  id?: string;
  project: string;
  type: string;
  payload: unknown;
  metadata?: Record<string, unknown>;
  priority?: number;
  runAfter?: number;
  targets?: string[];
  expiresAt?: number;
}

export function jobId(messageId: string, target: string): string {
  return target ? `${messageId}/${target}` : messageId;
}

export function enqueue(db: Database, m: NewMessage, now: number): string {
  const known = served.get(db);
  if (known && !known.listed.has(m.project)) known.listedAt = Number.NEGATIVE_INFINITY;
  const id = m.id ?? Bun.randomUUIDv7();
  const targets = m.targets?.length ? [...new Set(m.targets)] : [""];
  db.query<unknown, [string, string, string, string, string, number]>(
    "INSERT INTO messages (id, project_id, type, payload, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).run(id, m.project, m.type, JSON.stringify(m.payload), JSON.stringify(m.metadata ?? {}), now);
  const insert = db.query<
    unknown,
    [string, string, string, string, number, number, number | null, number]
  >(
    `INSERT INTO jobs (id, project_id, message_id, target, state, priority, run_after, expires_at, updated_at)
     VALUES (?, ?, ?, ?, 'ready', ?, ?, ?, ?)`,
  );
  for (const target of targets) {
    insert.run(
      jobId(id, target),
      m.project,
      id,
      target,
      m.priority ?? 0,
      m.runAfter ?? now,
      m.expiresAt ?? null,
      now,
    );
  }
  appendEvent(db, {
    messageId: id,
    kind: "queued",
    source: SOURCE,
    at: now,
    ...(m.targets?.length ? { data: { targets } } : {}),
  });
  return id;
}

export interface ClaimedJob {
  id: string;
  messageId: string;
  project: string;
  target: string;
  type: string;
  payload: unknown;
  metadata: Record<string, unknown>;
  createdAt: number;
  expiresAt: number | null;
  attempt: number;
  unresolvedAttempt: number | null;
  priority: number;
  path: string | null;
  node: string | null;
}

export interface ClaimFilter {
  paused?: string[];
  full?: string[];
}

interface LeasedRow {
  id: string;
  message_id: string;
  target: string;
  project_id: string;
  attempt: number;
  expires_at: number | null;
  unresolved_attempt: number | null;
  priority: number;
  path: string | null;
  node: string | null;
}

interface Fairness {
  tick: number;
  at: Map<string, number>;
  projects: string[];
  listed: Set<string>;
  listedAt: number;
  scanAll: boolean;
}

const served = new WeakMap<Database, Fairness>();

function fairnessOf(db: Database): Fairness {
  let s = served.get(db);
  if (!s) {
    s = {
      tick: 0,
      at: new Map(),
      projects: [],
      listed: new Set(),
      listedAt: Number.NEGATIVE_INFINITY,
      scanAll: true,
    };
    served.set(db, s);
  }
  const t = performance.now();
  if (t - s.listedAt > 1_000) {
    s.projects = db
      .query<{ id: string }, []>("SELECT id FROM projects UNION SELECT '_system'")
      .all()
      .map((r) => r.id);
    s.listed = new Set(s.projects);
    s.listedAt = t;
    s.scanAll = true;
  }
  return s;
}

const PATHS_OPEN = (paused: string, full: string) => `(path IS NULL OR (
           path NOT IN (SELECT value FROM json_each(${paused}))
           AND (priority = 0 OR path NOT IN (SELECT value FROM json_each(${full})))
         ))`;

const RETURNING =
  "RETURNING id, message_id, target, project_id, attempt, expires_at, unresolved_attempt, priority, path, node";

export function claim(
  db: Database,
  now: number,
  limit: number,
  leaseMs: number,
  filter: ClaimFilter = {},
): ClaimedJob[] {
  if (limit <= 0) return [];
  const paused = JSON.stringify(filter.paused ?? []);
  const full = JSON.stringify(filter.full ?? []);
  const nextPriority = db.query<{ p: number | null }, [number]>(
    "SELECT MIN(priority) AS p FROM jobs WHERE state = 'ready' AND priority > ?",
  );
  const lease = db.query<LeasedRow, [number, number, number, number, string, string, number]>(
    `UPDATE jobs SET state = 'leased', attempt = attempt + 1, lease_until = ?1, updated_at = ?2
     WHERE id IN (
       SELECT id FROM jobs
       WHERE state = 'ready' AND priority = ?3 AND run_after <= ?4
         AND ${SENDABLE("?4")}
         AND ${PATHS_OPEN("?5", "?6")}
       ORDER BY run_after
       LIMIT ?7
     )
     ${RETURNING}`,
  );
  const leaseFor = db.query<
    LeasedRow,
    [number, number, number, number, string, string, number, string]
  >(
    `UPDATE jobs SET state = 'leased', attempt = attempt + 1, lease_until = ?1, updated_at = ?2
     WHERE id IN (
       SELECT id FROM jobs
       WHERE state = 'ready' AND project_id = ?8 AND priority = ?3 AND run_after <= ?4
         AND ${SENDABLE("?4")}
         AND ${PATHS_OPEN("?5", "?6")}
       ORDER BY run_after
       LIMIT ?7
     )
     ${RETURNING}`,
  );
  const due = db.query<{ n: number }, [string, number, number]>(
    `SELECT 1 AS n FROM jobs
     WHERE state = 'ready' AND project_id = ? AND priority = ? AND run_after <= ? LIMIT 1`,
  );
  const state = fairnessOf(db);
  const projects =
    state.projects.length === 1
      ? state.projects
      : state.projects.toSorted((a, b) => (state.at.get(a) ?? 0) - (state.at.get(b) ?? 0));
  const leased: LeasedRow[] = [];
  let priority = Number.MIN_SAFE_INTEGER;
  while (leased.length < limit) {
    const next = nextPriority.get(priority)?.p;
    if (next === null || next === undefined) break;
    priority = next;
    const active = projects.filter((p) => due.get(p, priority, now) !== null);
    let more = false;
    for (let i = 0; i < active.length && leased.length < limit; i++) {
      const share = Math.ceil((limit - leased.length) / (active.length - i));
      const got = leaseFor.all(
        now + leaseMs,
        now,
        priority,
        now,
        paused,
        full,
        share,
        active[i] as string,
      );
      if (got.length === share) more = true;
      leased.push(...got);
    }
    if ((more || state.scanAll) && leased.length < limit) {
      leased.push(
        ...lease.all(now + leaseMs, now, priority, now, paused, full, limit - leased.length),
      );
    }
  }
  if (leased.length < limit) state.scanAll = false;
  if (leased.length === 0) return [];
  for (const r of leased) state.at.set(r.project_id, ++state.tick);

  const messages = new Map(
    db
      .query<
        { id: string; type: string; payload: string; metadata: string; created_at: number },
        [string]
      >(
        `SELECT id, type, payload, metadata, created_at FROM messages
         WHERE id IN (SELECT value FROM json_each(?))`,
      )
      .all(JSON.stringify([...new Set(leased.map((r) => r.message_id))]))
      .map((m) => [m.id, m]),
  );
  return leased.flatMap((r) => {
    const m = messages.get(r.message_id);
    if (!m) return [];
    return [
      {
        id: r.id,
        messageId: r.message_id,
        project: r.project_id,
        target: r.target,
        type: m.type,
        payload: JSON.parse(m.payload),
        metadata: JSON.parse(m.metadata),
        createdAt: m.created_at,
        expiresAt: r.expires_at,
        attempt: r.attempt,
        unresolvedAttempt: r.unresolved_attempt,
        priority: r.priority,
        path: r.path,
        node: r.node,
      },
    ];
  });
}

export interface SettleOptions {
  retry: RetryPolicy;
  reconcileMs: number;
  random?: () => number;
}

export type SettledJob = Pick<
  ClaimedJob,
  "id" | "messageId" | "target" | "attempt" | "createdAt" | "expiresAt"
>;

export function settle(
  db: Database,
  job: SettledJob,
  outcome: Outcome,
  now: number,
  opts: SettleOptions,
): Settled {
  const guard = "WHERE id = ? AND attempt = ? AND state IN ('leased', 'unknown')";
  const path = outcome.path ?? null;
  const event = (kind: string, data?: Record<string, unknown>) =>
    appendEvent(db, {
      messageId: job.messageId,
      kind,
      source: SOURCE,
      at: now,
      data: { attempt: job.attempt, ...(job.target ? { target: job.target } : {}), ...data },
    });
  const finish = (settled: Exclude<Settled, "stale">): Settled => {
    outcome.apply?.(db, settled, now);
    return settled;
  };

  switch (outcome.kind) {
    case "continue":
    case "done": {
      const r = db
        .query<unknown, [string | null, number, string, number]>(
          `UPDATE jobs SET state = 'done', path = coalesce(?, path), lease_until = NULL,
             check_after = NULL, last_error = NULL, unresolved_attempt = NULL, updated_at = ? ${guard}`,
        )
        .run(path, now, job.id, job.attempt);
      if (r.changes === 0) return "stale";
      event("done");
      return finish("done");
    }
    case "fail": {
      const dead = toDead(db, job, now, `${outcome.code}: ${outcome.reason}`, path, guard, () =>
        event("dead", { code: outcome.code, reason: outcome.reason }),
      );
      return dead === "stale" ? dead : finish(dead);
    }
    case "defer": {
      const { retry } = opts;
      const expired = job.expiresAt !== null && now >= job.expiresAt;
      if (expired || job.attempt >= retry.maxAttempts || now - job.createdAt >= retry.maxAgeMs) {
        const code = expired ? "expired" : "retries_exhausted";
        const why = expired
          ? `expired after ${job.attempt} attempts: ${outcome.reason}`
          : `retries exhausted after ${job.attempt} attempts: ${outcome.reason}`;
        const dead = toDead(db, job, now, why, path, guard, () =>
          event("dead", { code, reason: outcome.reason }),
        );
        return dead === "stale" ? dead : finish(dead);
      }
      let delay = outcome.delayMs ?? retryDelay(retry, job.attempt, opts.random);
      if (job.expiresAt !== null) delay = Math.min(delay, job.expiresAt - now);
      const row = db
        .query<{ notices: number }, [string, number]>(
          `SELECT notices FROM jobs WHERE id = ? AND attempt = ?
             AND state IN ('leased', 'unknown')`,
        )
        .get(job.id, job.attempt);
      if (!row) return "stale";
      let notices = row.notices;
      const due: number[] = [];
      while (
        notices < retry.noticesMs.length &&
        now - job.createdAt >= (retry.noticesMs[notices] as number)
      ) {
        due.push(retry.noticesMs[notices] as number);
        notices++;
      }
      db.query<unknown, [number, string, number, string | null, number, string, number]>(
        `UPDATE jobs SET state = 'ready', run_after = ?, last_error = ?, notices = ?,
           path = coalesce(?, path), lease_until = NULL, check_after = NULL,
           unresolved_attempt = NULL, updated_at = ? ${guard}`,
      ).run(now + delay, outcome.reason, notices, path, now, job.id, job.attempt);
      event("deferred", { reason: outcome.reason, delay_ms: delay });
      for (const after of due) event("delayed", { after_ms: after, reason: outcome.reason });
      return finish("retry");
    }
    case "requeue": {
      const r = db
        .query<unknown, [number, string | null, number, string, number]>(
          `UPDATE jobs SET state = 'ready', run_after = ?, attempt = attempt - 1,
             path = coalesce(?, path), lease_until = NULL, updated_at = ?
           WHERE id = ? AND attempt = ? AND state = 'leased'`,
        )
        .run(now + Math.max(0, outcome.delayMs), path, now, job.id, job.attempt);
      if (r.changes === 0) return "stale";
      return finish("requeued");
    }
    case "unknown": {
      const r = db
        .query<unknown, [number, string, string | null, number, string, number]>(
          `UPDATE jobs SET state = 'unknown', check_after = ?, last_error = ?,
             path = coalesce(?, path), lease_until = NULL, updated_at = ?
           WHERE id = ? AND attempt = ? AND state = 'leased'`,
        )
        .run(now + opts.reconcileMs, outcome.reason, path, now, job.id, job.attempt);
      if (r.changes === 0) return "stale";
      event("unknown", { reason: outcome.reason });
      return finish("unknown");
    }
  }
}

function toDead(
  db: Database,
  job: Pick<ClaimedJob, "id" | "attempt">,
  now: number,
  why: string,
  path: string | null,
  guard: string,
  record: () => void,
): "dead" | "stale" {
  const r = db
    .query<unknown, [string, string | null, number, string, number]>(
      `UPDATE jobs SET state = 'dead', last_error = ?, path = coalesce(?, path), lease_until = NULL,
         check_after = NULL, unresolved_attempt = NULL, updated_at = ? ${guard}`,
    )
    .run(why, path, now, job.id, job.attempt);
  if (r.changes === 0) return "stale";
  record();
  return "dead";
}

export function holdsLease(db: Database, job: Pick<ClaimedJob, "id" | "attempt">): boolean {
  return (
    db
      .query<unknown, [string, number]>(
        "SELECT 1 FROM jobs WHERE id = ? AND attempt = ? AND state = 'leased'",
      )
      .get(job.id, job.attempt) !== null
  );
}

export function renewLease(
  db: Database,
  job: Pick<ClaimedJob, "id" | "attempt">,
  until: number,
  now: number,
  node?: string | null,
): boolean {
  return (
    db
      .query<unknown, [number, number, number, string | null, string, number]>(
        `UPDATE jobs SET lease_until = ?, updated_at = ?, node = iif(?, ?, node)
         WHERE id = ? AND attempt = ? AND state = 'leased'`,
      )
      .run(until, now, node === undefined ? 0 : 1, node ?? null, job.id, job.attempt).changes > 0
  );
}

export function expireLeases(db: Database, now: number, reconcileMs: number): number {
  return markLeasesUnknown(db, now, now, reconcileMs, "lease expired");
}

export function recoverAfterCrash(db: Database, now: number, reconcileMs: number): number {
  return markLeasesUnknown(db, Number.MAX_SAFE_INTEGER, now, reconcileMs, "process restarted");
}

interface ChangedRow {
  message_id: string;
  target: string;
  attempt: number;
}

function changedEvent(db: Database, r: ChangedRow, kind: string, now: number, extra = {}) {
  appendEvent(db, {
    messageId: r.message_id,
    kind,
    source: SOURCE,
    at: now,
    data: { attempt: r.attempt, ...(r.target ? { target: r.target } : {}), ...extra },
  });
}

function markLeasesUnknown(
  db: Database,
  cutoff: number,
  now: number,
  reconcileMs: number,
  reason: string,
): number {
  const rows = db
    .query<ChangedRow, [number, string, number, number]>(
      `UPDATE jobs SET state = 'unknown', check_after = ?1, last_error = ?2, lease_until = NULL,
         updated_at = ?3
       WHERE state = 'leased' AND lease_until <= ?4
       RETURNING message_id, target, attempt`,
    )
    .all(now + reconcileMs, reason, now, cutoff);
  for (const r of rows) changedEvent(db, r, "unknown", now, { reason });
  return rows.length;
}

export function resendUnresolved(db: Database, now: number): number {
  const rows = db
    .query<ChangedRow, [number, number]>(
      `UPDATE jobs SET state = 'ready', run_after = ?1, check_after = NULL, updated_at = ?1,
         unresolved_attempt = attempt
       WHERE state = 'unknown' AND check_after <= ?2
       RETURNING message_id, target, attempt`,
    )
    .all(now, now);
  for (const r of rows) changedEvent(db, r, "duplicate_risk", now);
  return rows.length;
}

export function nextWakeAt(db: Database, now = Date.now()): number | undefined {
  const nextPriority = db.query<{ p: number | null }, [number]>(
    "SELECT MIN(priority) AS p FROM jobs WHERE state = 'ready' AND priority > ?",
  );
  const firstDue = db.query<{ t: number }, [number, number]>(
    `SELECT run_after AS t FROM jobs WHERE state = 'ready' AND priority = ?1 AND ${SENDABLE("?2")}
     ORDER BY run_after LIMIT 1`,
  );
  let t =
    db
      .query<{ t: number | null }, []>(
        `SELECT min(t) AS t FROM (
         SELECT min(lease_until) AS t FROM jobs WHERE state = 'leased'
         UNION ALL SELECT min(check_after) FROM jobs WHERE state = 'unknown'
       )`,
      )
      .get()?.t ?? null;
  let priority = Number.MIN_SAFE_INTEGER;
  for (;;) {
    const next = nextPriority.get(priority)?.p;
    if (next === null || next === undefined) break;
    priority = next;
    const due = firstDue.get(priority, now)?.t;
    if (due !== undefined && (t === null || due < t)) t = due;
  }
  return t ?? undefined;
}

export const HELD_OFFSET = 1e15;

export function holdProjectJobs(db: Database, project: string, now: number): number {
  return db
    .query<unknown, [number, number, string, number]>(
      `UPDATE jobs SET run_after = run_after + ?1, updated_at = ?2
       WHERE project_id = ?3 AND state = 'ready' AND run_after < ?4`,
    )
    .run(HELD_OFFSET, now, project, HELD_OFFSET).changes;
}

export function expireHeldJobs(db: Database, now: number): number {
  return db
    .query<unknown, [number, number]>(
      `UPDATE jobs SET run_after = ?1, updated_at = ?1
       WHERE state = 'ready' AND project_id IN (${PAUSED_PROJECTS})
         AND run_after >= ?2 AND expires_at IS NOT NULL AND expires_at <= ?1`,
    )
    .run(now, HELD_OFFSET).changes;
}

export function releaseProjectJobs(db: Database, project: string, now: number): number {
  return db
    .query<unknown, [number, number, string, number]>(
      `UPDATE jobs SET run_after = max(run_after - ?1, 0), updated_at = ?2
       WHERE project_id = ?3 AND state = 'ready' AND run_after >= ?4`,
    )
    .run(HELD_OFFSET, now, project, HELD_OFFSET).changes;
}

export function countByState(
  db: Database,
  project: string | null = null,
): Record<JobState, number> {
  const counts: Record<JobState, number> = { ready: 0, leased: 0, unknown: 0, done: 0, dead: 0 };
  for (const r of db
    .query<{ state: JobState; n: number }, [string | null]>(
      "SELECT state, count(*) AS n FROM jobs WHERE ?1 IS NULL OR project_id = ?1 GROUP BY state",
    )
    .all(project)) {
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
