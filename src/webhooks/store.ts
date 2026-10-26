import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import { b } from "../validate/schema.ts";

export const EVENT_TYPES = [
  "email.delivered",
  "email.delivery_delayed",
  "email.bounced",
  "email.complained",
  "email.unsubscribed",
  "email.suppressed",
  "email.failed",
  "email.canceled",
  "email.opened",
  "email.clicked",
  "project.limit_approaching",
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

export interface Webhook {
  id: string;
  url: string;
  events: EventType[];
  createdAt: number;
}

interface Row {
  id: string;
  url: string;
  events: string;
  created_at: number;
}

const fromRow = (r: Row): Webhook => ({
  id: r.id,
  url: r.url,
  events: b.array(b.enum(EVENT_TYPES)).parse(JSON.parse(r.events)),
  createdAt: r.created_at,
});

export function createWebhook(
  db: Database,
  project: ProjectId,
  url: string,
  events: EventType[],
  now: number,
): Webhook {
  const id = Bun.randomUUIDv7();
  const list = events.length ? [...new Set(events)] : [...EVENT_TYPES];
  db.query<unknown, [string, string, string, string, number]>(
    "INSERT INTO webhooks (id, project_id, url, events, created_at) VALUES (?, ?, ?, ?, ?)",
  ).run(id, project, url, JSON.stringify(list), now);
  return { id, url, events: list, createdAt: now };
}

export function listWebhooks(db: Database, project: ProjectId): Webhook[] {
  return db
    .query<Row, [string]>(
      `SELECT id, url, events, created_at FROM webhooks
       WHERE project_id = ? AND disabled_at IS NULL ORDER BY created_at`,
    )
    .all(project)
    .map(fromRow);
}

export function webhooksByProject(db: Database): Map<string, Webhook[]> {
  const out = new Map<string, Webhook[]>();
  const rows = db
    .query<Row & { project_id: string }, []>(
      `SELECT project_id, id, url, events, created_at FROM webhooks
       WHERE disabled_at IS NULL ORDER BY created_at`,
    )
    .all();
  for (const r of rows) {
    const list = out.get(r.project_id) ?? [];
    list.push(fromRow(r));
    out.set(r.project_id, list);
  }
  return out;
}

export function deleteWebhook(db: Database, project: ProjectId, id: string, now: number): boolean {
  return (
    db
      .query<unknown, [number, string, string]>(
        "UPDATE webhooks SET disabled_at = ? WHERE id = ? AND project_id = ? AND disabled_at IS NULL",
      )
      .run(now, id, project).changes > 0
  );
}

export interface Pending {
  id: string;
  webhookId: string;
  url: string;
  type: string;
  payload: string;
  attempt: number;
}

export const RETRY_MS = [
  5_000,
  5 * 60_000,
  30 * 60_000,
  2 * 3_600_000,
  5 * 3_600_000,
  10 * 3_600_000,
  10 * 3_600_000,
];

export function enabledWebhooks(db: Database): string[] {
  return db
    .query<{ id: string }, []>("SELECT id FROM webhooks WHERE disabled_at IS NULL ORDER BY id")
    .all()
    .map((r) => r.id);
}

export function claimFor(db: Database, webhookId: string, now: number, limit: number): Pending[] {
  return db
    .query<
      {
        id: string;
        webhook_id: string;
        url: string;
        type: string;
        payload: string;
        attempt: number;
      },
      [number, string, number]
    >(
      `UPDATE webhook_deliveries SET state = 'sending', attempt = attempt + 1, updated_at = ?1
       WHERE id IN (
         SELECT id FROM webhook_deliveries INDEXED BY webhook_deliveries_pending
         WHERE webhook_id = ?2 AND state = 'pending' AND next_at <= ?1
         ORDER BY next_at LIMIT ?3
       )
       RETURNING id, webhook_id, (SELECT url FROM webhooks WHERE id = webhook_id) AS url, type,
         payload, attempt`,
    )
    .all(now, webhookId, limit)
    .map((r) => ({
      id: r.id,
      webhookId: r.webhook_id,
      url: r.url,
      type: r.type,
      payload: r.payload,
      attempt: r.attempt,
    }));
}

export function settleDelivery(
  db: Database,
  d: Pick<Pending, "id" | "attempt">,
  ok: boolean,
  error: string | null,
  now: number,
  scale = 1,
): "done" | "retry" | "failed" {
  if (ok) {
    db.query<unknown, [number, string]>(
      "UPDATE webhook_deliveries SET state = 'done', last_error = NULL, updated_at = ? WHERE id = ?",
    ).run(now, d.id);
    return "done";
  }
  const wait = RETRY_MS[d.attempt - 1];
  if (wait === undefined) {
    db.query<unknown, [string | null, number, string]>(
      "UPDATE webhook_deliveries SET state = 'failed', last_error = ?, updated_at = ? WHERE id = ?",
    ).run(error, now, d.id);
    return "failed";
  }
  db.query<unknown, [number, string | null, number, string]>(
    `UPDATE webhook_deliveries SET state = 'pending', next_at = ?, last_error = ?, updated_at = ?
     WHERE id = ?`,
  ).run(now + Math.max(1, Math.round(wait * scale)), error, now, d.id);
  return "retry";
}

export function resetSending(db: Database, now: number): number {
  return db
    .query<unknown, [number]>(
      "UPDATE webhook_deliveries SET state = 'pending', updated_at = ? WHERE state = 'sending'",
    )
    .run(now).changes;
}

export function disableProjectWebhooks(db: Database, project: ProjectId, now: number): number {
  return db
    .query<unknown, [number, string]>(
      "UPDATE webhooks SET disabled_at = ? WHERE project_id = ? AND disabled_at IS NULL",
    )
    .run(now, project).changes;
}

const MAX_ERROR = 500;

export function recordAttempt(
  db: Database,
  a: {
    deliveryId: string;
    at: number;
    status: number | null;
    error: string | null;
    durationMs: number;
  },
): void {
  db.query<unknown, [string, number, number | null, string | null, number]>(
    `INSERT INTO webhook_attempts (delivery_id, at, status, error, duration_ms)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(a.deliveryId, a.at, a.status, a.error?.slice(0, MAX_ERROR) ?? null, a.durationMs);
}

export interface Attempt {
  at: number;
  status: number | null;
  error: string | null;
  durationMs: number;
}

export interface Delivery {
  id: string;
  type: string;
  state: "pending" | "sending" | "done" | "failed";
  createdAt: number;
  nextAt: number | null;
  attempts: Attempt[];
}

export interface DeliveryQuery {
  from?: number | undefined;
  to?: number | undefined;
  failed?: boolean | undefined;
  before?: string | undefined;
  limit: number;
}

const ownWebhook = (db: Database, project: ProjectId, id: string) =>
  db
    .query<{ id: string }, [string, string]>(
      "SELECT id FROM webhooks WHERE id = ? AND project_id = ?",
    )
    .get(id, project) !== null;

export function listDeliveries(
  db: Database,
  project: ProjectId,
  webhookId: string,
  q: DeliveryQuery,
): Delivery[] | null {
  if (!ownWebhook(db, project, webhookId)) return null;
  const rows = db
    .query<
      { id: string; type: string; state: Delivery["state"]; created_at: number; next_at: number },
      [string, number, number, number, string | null, number]
    >(
      `SELECT id, type, state, created_at, next_at FROM webhook_deliveries
       WHERE webhook_id = ?1 AND created_at >= ?2 AND created_at < ?3
         AND (?4 = 0 OR state = 'failed') AND (?5 IS NULL OR id < ?5)
       ORDER BY id DESC LIMIT ?6`,
    )
    .all(
      webhookId,
      q.from ?? 0,
      q.to ?? Number.MAX_SAFE_INTEGER,
      q.failed ? 1 : 0,
      q.before ?? null,
      q.limit,
    );
  const attempts = db.query<
    { at: number; status: number | null; error: string | null; duration_ms: number },
    [string]
  >(
    "SELECT at, status, error, duration_ms FROM webhook_attempts WHERE delivery_id = ? ORDER BY id",
  );
  return rows.map((r) => ({
    id: r.id,
    type: r.type,
    state: r.state,
    createdAt: r.created_at,
    nextAt: r.state === "pending" ? r.next_at : null,
    attempts: attempts.all(r.id).map((a) => ({
      at: a.at,
      status: a.status,
      error: a.error,
      durationMs: a.duration_ms,
    })),
  }));
}

export function resendDelivery(
  db: Database,
  project: ProjectId,
  webhookId: string,
  deliveryId: string,
  now: number,
): "resent" | "not-found" | "in-flight" {
  if (!ownWebhook(db, project, webhookId)) return "not-found";
  const row = db
    .query<{ state: string }, [string, string]>(
      "SELECT state FROM webhook_deliveries WHERE id = ? AND webhook_id = ?",
    )
    .get(deliveryId, webhookId);
  if (!row) return "not-found";
  if (row.state === "pending" || row.state === "sending") return "in-flight";
  db.query<unknown, [number, string]>(
    `UPDATE webhook_deliveries SET state = 'pending', attempt = 0, next_at = ?1, updated_at = ?1
     WHERE id = ?2`,
  ).run(now, deliveryId);
  return "resent";
}

export interface Resend {
  id: string;
  webhookId: string;
  from: number;
  to: number;
  failed: boolean;
  resent: number;
  state: "queued" | "done";
  createdAt: number;
  updatedAt: number;
}

interface ResendRow {
  id: string;
  webhook_id: string;
  from_at: number;
  to_at: number;
  failed_only: number;
  cursor: string | null;
  resent: number;
  state: Resend["state"];
  created_at: number;
  updated_at: number;
}

const resendOf = (r: ResendRow): Resend => ({
  id: r.id,
  webhookId: r.webhook_id,
  from: r.from_at,
  to: r.to_at,
  failed: r.failed_only === 1,
  resent: r.resent,
  state: r.state,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

export function queueResend(
  db: Database,
  project: ProjectId,
  webhookId: string,
  range: { from: number; to: number; failed: boolean },
  now: number,
): Resend | { busy: string } | null {
  if (!ownWebhook(db, project, webhookId)) return null;
  const running = db
    .query<{ id: string }, [string]>(
      "SELECT id FROM webhook_resends WHERE webhook_id = ? AND state = 'queued'",
    )
    .get(webhookId);
  if (running) return { busy: running.id };
  const id = Bun.randomUUIDv7();
  db.query<unknown, [string, string, number, number, number, number]>(
    `INSERT INTO webhook_resends (id, webhook_id, from_at, to_at, failed_only, state, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, ?6)`,
  ).run(id, webhookId, range.from, range.to, range.failed ? 1 : 0, now);
  return {
    id,
    webhookId,
    ...range,
    resent: 0,
    state: "queued",
    createdAt: now,
    updatedAt: now,
  };
}

export function getResend(
  db: Database,
  project: ProjectId,
  webhookId: string,
  id: string,
): Resend | null {
  if (!ownWebhook(db, project, webhookId)) return null;
  const row = db
    .query<ResendRow, [string, string]>(
      "SELECT * FROM webhook_resends WHERE id = ? AND webhook_id = ?",
    )
    .get(id, webhookId);
  return row ? resendOf(row) : null;
}

export interface ResendLimits {
  batch: number;
  maxWaiting: number;
  jobs: number;
}

export const RESEND_LIMITS: ResendLimits = { batch: 50, maxWaiting: 200, jobs: 10 };

export function resendStep(db: Database, now: number, limits = RESEND_LIMITS): number {
  const jobs = db
    .query<ResendRow, [number]>(
      `SELECT r.* FROM webhook_resends r JOIN webhooks w ON w.id = r.webhook_id
       WHERE r.state = 'queued' AND w.disabled_at IS NULL ORDER BY r.created_at LIMIT ?`,
    )
    .all(limits.jobs);
  let moved = 0;
  for (const job of jobs) {
    const waiting =
      db
        .query<{ n: number }, [string]>(
          `SELECT count(*) AS n FROM webhook_deliveries
           WHERE webhook_id = ? AND state IN ('pending', 'sending')`,
        )
        .get(job.webhook_id)?.n ?? 0;
    const room = Math.min(limits.batch, limits.maxWaiting - waiting);
    if (room <= 0) continue;
    const ids = db
      .query<{ id: string }, [string, number, number, number, string | null, number]>(
        `SELECT id FROM webhook_deliveries
         WHERE webhook_id = ?1 AND created_at >= ?2 AND created_at < ?3
           AND state IN ('done', 'failed') AND (?4 = 0 OR state = 'failed')
           AND (?5 IS NULL OR id > ?5)
         ORDER BY id LIMIT ?6`,
      )
      .all(job.webhook_id, job.from_at, job.to_at, job.failed_only, job.cursor, room)
      .map((r) => r.id);
    const move = db.query<unknown, [number, string]>(
      `UPDATE webhook_deliveries SET state = 'pending', attempt = 0, next_at = ?1, updated_at = ?1
       WHERE id = ?2`,
    );
    for (const id of ids) move.run(now, id);
    moved += ids.length;
    db.query<unknown, [string | null, number, string, number, string]>(
      `UPDATE webhook_resends SET cursor = ?1, resent = resent + ?2, state = ?3, updated_at = ?4
       WHERE id = ?5`,
    ).run(ids.at(-1) ?? job.cursor, ids.length, ids.length < room ? "done" : "queued", now, job.id);
  }
  return moved;
}
