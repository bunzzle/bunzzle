import type { Database } from "bun:sqlite";
import { appendEvent } from "../core/events.ts";
import { enqueue, jobId } from "../core/jobs.ts";
import type { SealedBody } from "../crypto/envelope.ts";
import { countEmail, indexEmail } from "../emails/search.ts";
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
  runAfter?: number;
  expiresAt?: number;
  metadata?: Record<string, unknown>;
  suppressed?: Map<string, { reason: string; scope: string }>;
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
      ...(email.runAfter !== undefined ? { runAfter: email.runAfter } : {}),
      ...(email.metadata ? { metadata: email.metadata } : {}),
    },
    now,
  );
  const insert = db.query<unknown, [string, string, number]>(
    "INSERT INTO recipients (job_id, address, status, updated_at) VALUES (?, ?, 'queued', ?)",
  );
  const blocked = db.query<unknown, [string, string, string, number]>(
    `INSERT INTO recipients (job_id, address, status, class, reply, updated_at)
     VALUES (?, ?, 'failed', 'suppressed', ?, ?)`,
  );
  const meta = email.metadata ?? {};
  indexEmail(db, {
    id,
    domain: domainOf(email.from),
    keyId: (meta["apiKeyId"] as string | null | undefined) ?? null,
    test: meta["test"] === true,
    tags: (meta["tags"] as { name: string; value: string }[] | undefined) ?? [],
  });
  let sent = 0;
  let suppressedCount = 0;
  for (const [domain, addresses] of byDomain) {
    let live = 0;
    for (const address of addresses) {
      const s = email.suppressed?.get(address);
      if (s) {
        blocked.run(jobId(id, domain), address, `suppressed (${s.reason})`, now);
        suppressedCount++;
        appendEvent(db, {
          messageId: id,
          kind: "suppressed",
          source: "intake",
          at: now,
          data: { address, reason: s.reason, scope: s.scope },
        });
      } else {
        insert.run(jobId(id, domain), address, now);
        live++;
        sent++;
      }
    }
    if (live === 0) {
      db.query<unknown, [number, string]>(
        "UPDATE jobs SET state = 'done', updated_at = ? WHERE id = ?",
      ).run(now, jobId(id, domain));
    }
  }
  countEmail(db, id, "sent", sent, now);
  countEmail(db, id, "suppressed", suppressedCount, now);
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
  db.query<unknown, [number]>(
    "UPDATE inbound SET raw = NULL, wrapped = NULL, epoch = NULL WHERE received_at < ? AND raw IS NOT NULL",
  ).run(now - retentionMs);
  db.query<unknown, [number]>(
    "DELETE FROM webhook_deliveries WHERE state IN ('done', 'failed') AND updated_at < ?",
  ).run(now - retentionMs);
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

export interface ScheduledEmail {
  from: string;
  scheduledAt: number | null;
}

export function scheduledEmail(db: Database, id: string): ScheduledEmail | null {
  const row = db
    .query<{ payload: string; metadata: string }, [string]>(
      "SELECT payload, metadata FROM messages WHERE id = ? AND type = 'email'",
    )
    .get(id);
  if (!row) return null;
  const payload = JSON.parse(row.payload) as Partial<EmailPayload>;
  const meta = JSON.parse(row.metadata) as { scheduledAt?: number | null };
  return { from: payload.from ?? "", scheduledAt: meta.scheduledAt ?? null };
}

function notStarted(db: Database, id: string): boolean {
  const jobs = db
    .query<{ state: string; attempt: number }, [string]>(
      "SELECT state, attempt FROM jobs WHERE message_id = ?",
    )
    .all(id);
  return (
    jobs.some((j) => j.state === "ready") &&
    jobs.every((j) => j.attempt === 0 && j.state !== "leased" && j.state !== "unknown")
  );
}

export function cancelEmail(db: Database, id: string, now: number): "ok" | "started" {
  if (!notStarted(db, id)) return "started";
  db.query<unknown, [number, string]>(
    "UPDATE jobs SET state = 'dead', last_error = 'canceled', updated_at = ? WHERE message_id = ? AND state = 'ready'",
  ).run(now, id);
  db.query<unknown, [number, string]>(
    `UPDATE recipients SET status = 'failed', class = 'canceled', reply = 'canceled', updated_at = ?
     WHERE status = 'queued' AND job_id IN (SELECT id FROM jobs WHERE message_id = ?)`,
  ).run(now, id);
  db.query<unknown, [string]>("DELETE FROM bodies WHERE message_id = ?").run(id);
  appendEvent(db, { messageId: id, kind: "canceled", source: "api", at: now });
  return "ok";
}

export function rescheduleEmail(
  db: Database,
  id: string,
  at: number,
  now: number,
): "ok" | "started" | "expires" {
  if (!notStarted(db, id)) return "started";
  const exp = db
    .query<{ t: number | null }, [string]>(
      "SELECT min(expires_at) AS t FROM jobs WHERE message_id = ? AND state = 'ready'",
    )
    .get(id)?.t;
  if (exp !== null && exp !== undefined && at >= exp) return "expires";
  db.query<unknown, [number, number, string]>(
    "UPDATE jobs SET run_after = ?, updated_at = ? WHERE message_id = ? AND state = 'ready'",
  ).run(at, now, id);
  db.query<unknown, [number, string]>(
    "UPDATE messages SET metadata = json_set(metadata, '$.scheduledAt', ?) WHERE id = ?",
  ).run(at, id);
  appendEvent(db, {
    messageId: id,
    kind: "rescheduled",
    source: "api",
    at: now,
    data: { scheduled_at: new Date(at).toISOString() },
  });
  return "ok";
}
