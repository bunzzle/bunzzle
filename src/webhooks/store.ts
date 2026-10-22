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

export function claimDeliveries(db: Database, now: number, limit: number): Pending[] {
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
      [number, number, number]
    >(
      `UPDATE webhook_deliveries SET state = 'sending', attempt = attempt + 1, updated_at = ?1
       WHERE id IN (
         SELECT d.id FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id
         WHERE d.state = 'pending' AND d.next_at <= ?1 AND w.disabled_at IS NULL
         ORDER BY d.next_at LIMIT ?3
       )
       RETURNING id, webhook_id, (SELECT url FROM webhooks WHERE id = webhook_id) AS url, type,
         payload, attempt`,
    )
    .all(now, now, limit)
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
export const MAX_RESEND = 10_000;

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

export function resendRange(
  db: Database,
  project: ProjectId,
  webhookId: string,
  range: { from: number; to: number; failed: boolean },
  now: number,
): { resent: number } | { tooMany: number } | null {
  if (!ownWebhook(db, project, webhookId)) return null;
  const where = `webhook_id = ?1 AND created_at >= ?2 AND created_at < ?3
    AND state IN ('done', 'failed') AND (?4 = 0 OR state = 'failed')`;
  const args = [webhookId, range.from, range.to, range.failed ? 1 : 0] as const;
  const n =
    db
      .query<{ n: number }, [string, number, number, number]>(
        `SELECT count(*) AS n FROM webhook_deliveries WHERE ${where}`,
      )
      .get(...args)?.n ?? 0;
  if (n > MAX_RESEND) return { tooMany: n };
  const resent = db
    .query<unknown, [string, number, number, number, number]>(
      `UPDATE webhook_deliveries SET state = 'pending', attempt = 0, next_at = ?5, updated_at = ?5
       WHERE ${where}`,
    )
    .run(...args, now).changes;
  return { resent };
}
