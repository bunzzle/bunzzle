import type { Database } from "bun:sqlite";
import { appendEvent } from "../core/events.ts";
import { enqueue, jobId } from "../core/jobs.ts";
import type { SealedBody } from "../crypto/envelope.ts";
import { domainOf, normalizeAddress } from "../mime/address.ts";

export interface EmailPayload {
  from: string;
  smtpUtf8: boolean;
  requireTls: boolean;
}

export interface NewEmail extends EmailPayload {
  id: string;
  body: SealedBody;
  recipients: string[];
  priority?: number;
  expiresAt?: number;
  metadata?: Record<string, unknown>;
}

export type RecipientState = "queued" | "deferred" | "unknown" | "delivered" | "bounced" | "failed";

export const PENDING: readonly RecipientState[] = ["queued", "deferred", "unknown"];

export interface RecipientRow {
  job_id: string;
  address: string;
  status: RecipientState;
  attempts: number;
  code: number | null;
  enhanced: string | null;
  reply: string | null;
  class: string | null;
  scope: string | null;
  suppress: number;
  updated_at: number;
}

export function enqueueEmail(db: Database, email: NewEmail, now: number): string {
  const byDomain = new Map<string, string[]>();
  for (const raw of email.recipients) {
    const address = normalizeAddress(raw);
    const domain = domainOf(address);
    const list = byDomain.get(domain) ?? [];
    if (!list.includes(address)) list.push(address);
    byDomain.set(domain, list);
  }
  if (byDomain.size === 0) throw new Error("an email needs at least one recipient");
  const payload: EmailPayload = {
    from: email.from,
    smtpUtf8: email.smtpUtf8,
    requireTls: email.requireTls,
  };
  const id = enqueue(
    db,
    {
      id: email.id,
      type: "email",
      payload,
      targets: [...byDomain.keys()],
      ...(email.priority !== undefined ? { priority: email.priority } : {}),
      ...(email.expiresAt !== undefined ? { expiresAt: email.expiresAt } : {}),
      ...(email.metadata ? { metadata: email.metadata } : {}),
    },
    now,
  );
  const insert = db.query<unknown, [string, string, number]>(
    "INSERT INTO recipients (job_id, address, status, updated_at) VALUES (?, ?, 'queued', ?)",
  );
  for (const [domain, addresses] of byDomain) {
    for (const address of addresses) insert.run(jobId(id, domain), address, now);
  }
  db.query<unknown, [string, number, Uint8Array, Uint8Array]>(
    "INSERT INTO bodies (message_id, epoch, wrapped, body) VALUES (?, ?, ?, ?)",
  ).run(id, email.body.epoch, email.body.wrapped, email.body.body);
  return id;
}

export function emailExists(db: Database, id: string): boolean {
  return (
    db.query<{ n: number }, [string]>("SELECT 1 AS n FROM messages WHERE id = ?").get(id) !== null
  );
}

export function bodyOf(db: Database, messageId: string): SealedBody | null {
  const r = db
    .query<{ epoch: number; wrapped: Uint8Array; body: Uint8Array }, [string]>(
      "SELECT epoch, wrapped, body FROM bodies WHERE message_id = ?",
    )
    .get(messageId);
  return r
    ? { epoch: r.epoch, wrapped: new Uint8Array(r.wrapped), body: new Uint8Array(r.body) }
    : null;
}

export function shredBodies(db: Database, now: number, retentionMs: number): string[] {
  const ids = db
    .query<{ message_id: string }, [number]>(
      `DELETE FROM bodies WHERE message_id IN (
         SELECT m.id FROM messages m
         WHERE m.created_at < ?
           AND NOT EXISTS (
             SELECT 1 FROM jobs j
             WHERE j.message_id = m.id AND j.state IN ('ready', 'leased', 'unknown')
           )
       )
       RETURNING message_id`,
    )
    .all(now - retentionMs)
    .map((r) => r.message_id);
  for (const id of ids)
    appendEvent(db, { messageId: id, kind: "shredded", source: "retention", at: now });
  return ids;
}

export function recipientsOf(db: Database, messageId: string): RecipientRow[] {
  return db
    .query<RecipientRow, [string]>(
      `SELECT r.* FROM recipients r JOIN jobs j ON j.id = r.job_id
       WHERE j.message_id = ? ORDER BY r.job_id, r.address`,
    )
    .all(messageId);
}

export function pendingRecipients(db: Database, job: string): string[] {
  return db
    .query<{ address: string }, [string]>(
      `SELECT address FROM recipients
       WHERE job_id = ? AND status IN ('queued', 'deferred', 'unknown') ORDER BY rowid`,
    )
    .all(job)
    .map((r) => r.address);
}
