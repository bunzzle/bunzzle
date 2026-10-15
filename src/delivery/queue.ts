import type { Database } from "bun:sqlite";
import { enqueue, jobId } from "../core/jobs.ts";
import { domainOf, normalizeAddress } from "../mime/address.ts";

export interface EmailPayload {
  from: string;
  data: string;
  smtpUtf8: boolean;
  requireTls: boolean;
}

export interface NewEmail extends EmailPayload {
  id?: string;
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
    data: email.data,
    smtpUtf8: email.smtpUtf8,
    requireTls: email.requireTls,
  };
  const id = enqueue(
    db,
    {
      ...(email.id ? { id: email.id } : {}),
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
  return id;
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
