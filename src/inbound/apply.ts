import type { Database } from "bun:sqlite";
import { appendEvent } from "../core/events.ts";
import type { SealedBody } from "../crypto/envelope.ts";
import { countEmail } from "../emails/search.ts";
import { attributionOf, countSender } from "../guards/guards.ts";
import { countWarmup } from "../ips/warmup.ts";
import { classify } from "../replies/classify.ts";
import { suppress, suppressionForClass } from "../suppressions/store.ts";
import type { Report } from "./parse.ts";

export type Via = "bounce" | "unsubscribe" | "feedback";

export interface InboundInput {
  id: string;
  via: Via;
  messageId: string | null;
  report: Report;
  raw: SealedBody | null;
  simulated?: boolean;
}

export interface Applied {
  kind: string;
  recipients: string[];
}

const SOURCE = "inbound";

interface RecipientRow {
  job_id: string;
  address: string;
  status: string;
}

function recipientsOf(db: Database, messageId: string): RecipientRow[] {
  return db
    .query<RecipientRow, [string]>(
      `SELECT r.job_id, r.address, r.status FROM recipients r JOIN jobs j ON j.id = r.job_id
       WHERE j.message_id = ?`,
    )
    .all(messageId);
}

function codeOf(text: string | null): number | null {
  const m = text ? /^\s*([245]\d\d)\b/.exec(text) : null;
  return m ? Number(m[1]) : null;
}

export function applyUnsubscribe(
  db: Database,
  messageId: string,
  via: "mailto" | "one-click",
  now: number,
): string | null {
  const rows = recipientsOf(db, messageId);
  if (rows.length !== 1) return null;
  const address = (rows[0] as RecipientRow).address;
  suppress(db, { address, scope: "bulk", reason: "unsubscribe", messageId }, now);
  appendEvent(db, {
    messageId,
    kind: "unsubscribed",
    source: SOURCE,
    at: now,
    data: { address, via },
  });
  countEmail(db, messageId, "unsubscribed", 1, now);
  return address;
}

export function applyInbound(db: Database, input: InboundInput, now: number): Applied {
  const { report, messageId } = input;
  db.query<
    unknown,
    [
      string,
      number,
      string,
      string | null,
      string,
      number | null,
      Uint8Array | null,
      Uint8Array | null,
    ]
  >(
    `INSERT INTO inbound (id, received_at, kind, message_id, parsed, epoch, wrapped, raw)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    input.id,
    now,
    input.via === "unsubscribe" ? "unsubscribe" : report.kind,
    messageId,
    JSON.stringify(report),
    input.raw?.epoch ?? null,
    input.raw?.wrapped ?? null,
    input.raw?.body ?? null,
  );
  if (!messageId) return { kind: "unmatched", recipients: [] };
  const rows = recipientsOf(db, messageId);
  if (rows.length === 0) return { kind: "unmatched", recipients: [] };
  const event = (kind: string, data: Record<string, unknown>) =>
    appendEvent(db, { messageId, kind, source: SOURCE, at: now, data });
  const byAddress = new Map(rows.map((r) => [r.address.toLowerCase(), r]));
  const sole = rows.length === 1 ? (rows[0] as RecipientRow) : null;

  if (input.via === "unsubscribe") {
    const address = applyUnsubscribe(db, messageId, "mailto", now);
    return address
      ? { kind: "unsubscribe", recipients: [address] }
      : { kind: "unmatched", recipients: [] };
  }

  const who = attributionOf(db, messageId);
  const attribute = (delta: { hardBounced?: number; complained?: number }) => {
    if (!who || input.simulated) return;
    countSender(db, who.domain, who.lane, delta, now);
    if (who.source) {
      countWarmup(
        db,
        who.source,
        who.bucket,
        { bounced: delta.hardBounced ?? 0, complained: delta.complained ?? 0 },
        now,
      );
    }
  };

  if (report.kind === "arf") {
    const target =
      (report.originalRcpt ? byAddress.get(report.originalRcpt) : undefined) ?? sole ?? undefined;
    if (!target) return { kind: "unmatched", recipients: [] };
    suppress(
      db,
      {
        address: target.address,
        scope: "bulk",
        reason: "complaint",
        detail: report.feedbackType,
        messageId,
      },
      now,
    );
    event("complained", { address: target.address, feedback_type: report.feedbackType });
    countEmail(db, messageId, "complained", 1, now);
    attribute({ complained: 1 });
    return { kind: "complaint", recipients: [target.address] };
  }

  const failures: { row: RecipientRow; status: string | null; diagnostic: string }[] = [];
  if (report.kind === "dsn") {
    for (const r of report.recipients) {
      const row = byAddress.get(r.address) ?? (report.recipients.length === 1 ? sole : undefined);
      if (!row) continue;
      if (r.action === "failed") {
        failures.push({ row, status: r.status, diagnostic: r.diagnostic ?? r.status ?? "failed" });
      } else if (r.action === "delayed") {
        event("delay_reported", {
          address: row.address,
          status: r.status,
          diagnostic: r.diagnostic,
        });
      }
    }
  } else if (report.kind === "bounce") {
    const matched = report.addresses.flatMap((a) => {
      const row = byAddress.get(a);
      return row ? [row] : [];
    });
    for (const row of matched.length > 0 ? matched : sole ? [sole] : []) {
      failures.push({ row, status: report.status, diagnostic: report.diagnostic });
    }
  } else {
    event("inbound_ignored", { kind: report.kind });
    return { kind: report.kind, recipients: [] };
  }

  const update = db.query<
    unknown,
    [string, string | null, string, number | null, string | null, number, string, string]
  >(
    `UPDATE recipients SET status = 'bounced', class = ?, scope = ?, reply = ?, code = ?, enhanced = ?,
       suppress = ?, updated_at = ${now} WHERE job_id = ? AND address = ?`,
  );
  for (const f of failures) {
    const enhanced = f.status && /^[245]\.\d{1,3}\.\d{1,3}$/.test(f.status) ? f.status : null;
    const verdict = classify({
      phase: "rcpt",
      code: codeOf(f.diagnostic) ?? (enhanced?.startsWith("4") ? 450 : 550),
      enhanced,
      text: f.diagnostic,
    });
    if (verdict.permanent === false) {
      event("delay_reported", {
        address: f.row.address,
        status: f.status,
        diagnostic: f.diagnostic,
      });
      continue;
    }
    update.run(
      verdict.class,
      verdict.scope,
      f.diagnostic,
      codeOf(f.diagnostic),
      enhanced,
      verdict.suppress ? 1 : 0,
      f.row.job_id,
      f.row.address,
    );
    if (f.row.status !== "bounced") countEmail(db, messageId, "bounced", 1, now);
    event("bounced", {
      address: f.row.address,
      async: true,
      was: f.row.status,
      class: verdict.class,
      about: verdict.scope,
      reply: f.diagnostic,
    });
    const s = verdict.suppress ? suppressionForClass(verdict.class) : null;
    if (s) attribute({ hardBounced: 1 });
    if (s) {
      suppress(
        db,
        {
          address: f.row.address,
          scope: s.scope,
          reason: s.reason,
          detail: f.diagnostic,
          messageId,
          ttlMs: s.ttlMs,
        },
        now,
      );
      event("address_suppressed", {
        address: f.row.address,
        reason: s.reason,
        scope: s.scope,
        class: verdict.class,
      });
    }
  }
  return { kind: "bounce", recipients: failures.map((f) => f.row.address) };
}
