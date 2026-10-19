import type { Database } from "bun:sqlite";
import { z } from "zod";

export const EVENT_TYPES = [
  "email.delivered",
  "email.delivery_delayed",
  "email.bounced",
  "email.complained",
  "email.unsubscribed",
  "email.suppressed",
  "email.failed",
  "email.canceled",
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
  events: z.array(z.enum(EVENT_TYPES)).parse(JSON.parse(r.events)),
  createdAt: r.created_at,
});

export function createWebhook(
  db: Database,
  url: string,
  events: EventType[],
  now: number,
): Webhook {
  const id = Bun.randomUUIDv7();
  const list = events.length ? [...new Set(events)] : [...EVENT_TYPES];
  db.query<unknown, [string, string, string, number]>(
    "INSERT INTO webhooks (id, url, events, created_at) VALUES (?, ?, ?, ?)",
  ).run(id, url, JSON.stringify(list), now);
  return { id, url, events: list, createdAt: now };
}

export function listWebhooks(db: Database): Webhook[] {
  return db
    .query<Row, []>(
      "SELECT id, url, events, created_at FROM webhooks WHERE disabled_at IS NULL ORDER BY created_at",
    )
    .all()
    .map(fromRow);
}

export function deleteWebhook(db: Database, id: string, now: number): boolean {
  return (
    db
      .query<unknown, [number, string]>(
        "UPDATE webhooks SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL",
      )
      .run(now, id).changes > 0
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
