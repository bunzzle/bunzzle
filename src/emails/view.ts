import type { Database } from "bun:sqlite";
import { eventsFor } from "../core/events.ts";
import { recipientsOf } from "../delivery/queue.ts";

export type PublicStatus =
  | "scheduled"
  | "queued"
  | "sending"
  | "delivery_delayed"
  | "delivered"
  | "bounced"
  | "failed"
  | "expired"
  | "suppressed"
  | "canceled";

export interface EmailMeta {
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  replyTo: string[];
  tags: { name: string; value: string }[];
  apiKeyId: string | null;
  scheduledAt: number | null;
  lane: "transactional" | "bulk";
}

const iso = (t: number | null | undefined) =>
  typeof t === "number" ? new Date(t).toISOString() : null;

function recipientStatus(status: string, cls: string | null, scheduled: boolean): PublicStatus {
  switch (status) {
    case "queued":
      return scheduled ? "scheduled" : "queued";
    case "deferred":
      return "delivery_delayed";
    case "unknown":
      return "sending";
    case "delivered":
      return "delivered";
    case "bounced":
      return "bounced";
    default:
      if (cls === "suppressed") return "suppressed";
      if (cls === "canceled") return "canceled";
      return cls === "expired" ? "expired" : "failed";
  }
}

function emailStatus(all: PublicStatus[]): PublicStatus {
  const final = new Set<PublicStatus>([
    "delivered",
    "bounced",
    "failed",
    "expired",
    "suppressed",
    "canceled",
  ]);
  if (all.every((s) => final.has(s))) {
    for (const s of ["canceled", "bounced", "failed", "expired", "suppressed"] as const) {
      if (all.includes(s)) return s;
    }
    return "delivered";
  }
  for (const s of ["delivery_delayed", "sending", "queued", "scheduled"] as const) {
    if (all.includes(s)) return s;
  }
  return "queued";
}

export function emailView(db: Database, id: string, now: number) {
  const msg = db
    .query<{ id: string; metadata: string; created_at: number }, [string]>(
      "SELECT id, metadata, created_at FROM messages WHERE id = ? AND type = 'email'",
    )
    .get(id);
  if (!msg) return null;
  const meta = JSON.parse(msg.metadata) as Partial<EmailMeta>;
  const scheduled = (meta.scheduledAt ?? 0) > now;
  const rows = recipientsOf(db, id);
  const recipients = rows.map((r) => ({
    email: r.address,
    status: recipientStatus(r.status, r.class, scheduled),
    attempts: r.attempts,
    last_reply: r.reply,
    class: r.class,
    about: r.scope,
    suppression_candidate: r.suppress === 1,
    updated_at: iso(r.updated_at),
  }));
  const events = eventsFor(db, id);
  const conversation = db.query<{ session: number; data: string }, [string, number]>(
    "SELECT session, data FROM conversations WHERE message_id = ? AND attempt_at = ? ORDER BY session",
  );
  const recipientEvents = events.filter((e) => e.kind === "recipient");
  const attempts = events
    .filter((e) => e.kind === "attempt")
    .map((e) => {
      const d = e.data ?? {};
      const target = String(d["target"] ?? "");
      const sessions = (d["sessions"] as Record<string, unknown>[] | undefined) ?? [];
      const talks = new Map(
        conversation.all(id, e.occurred_at).map((c) => [c.session, c.data] as const),
      );
      return {
        at: iso(e.occurred_at),
        domain: target,
        mx: d["mx"] ?? [],
        provider: d["provider"] ?? null,
        via: d["via"] === "relay" ? "relay" : "direct",
        tls_policy: (d["policy"] as { rule?: string } | null)?.rule ?? null,
        reconciled: d["recalled"] === true,
        sessions: sessions.map((s, i) => {
          const tls = (s["tls"] ?? {}) as Record<string, unknown>;
          return {
            host: s["host"],
            ip: s["address"],
            reused_connection: s["reused"] === true,
            tls: {
              status: tls["status"] ?? "none",
              version: tls["version"] ?? null,
              cipher: tls["cipher"] ?? null,
              rule: tls["rule"] ?? null,
              error: tls["error"] ?? null,
            },
            stopped_at: s["phase"] === "done" ? null : s["phase"],
            error: s["error"] ?? null,
            conversation: (JSON.parse(talks.get(i) ?? "[]") as [number, string, string][]).map(
              ([ms, who, text]) => ({
                at_ms: ms,
                from: who === "C" ? "client" : who === "S" ? "server" : "note",
                text,
              }),
            ),
          };
        }),
        results: recipientEvents
          .filter(
            (r) =>
              r.occurred_at === e.occurred_at &&
              String(r.data?.["address"] ?? "").endsWith(`@${target}`),
          )
          .map((r) => ({
            email: r.data?.["address"],
            status: r.data?.["status"],
            reply: r.data?.["reply"],
            class: r.data?.["class"],
            action: r.data?.["action"],
          })),
      };
    });
  return {
    object: "email",
    id: msg.id,
    from: meta.from ?? null,
    to: meta.to ?? [],
    cc: meta.cc ?? [],
    bcc: meta.bcc ?? [],
    reply_to: meta.replyTo ?? [],
    subject: null,
    html: null,
    text: null,
    tags: meta.tags ?? [],
    lane: meta.lane ?? "transactional",
    created_at: iso(msg.created_at),
    scheduled_at: iso(meta.scheduledAt ?? null),
    last_event: emailStatus(recipients.map((r) => r.status)),
    recipients,
    attempts,
    events: events
      .filter((e) => e.kind !== "attempt" && e.kind !== "recipient")
      .map((e) => ({ type: e.kind, at: iso(e.occurred_at), ...(e.data ?? {}) })),
  };
}

export type EmailView = NonNullable<ReturnType<typeof emailView>>;

export function pruneConversations(db: Database, before: number): number {
  return db.query<unknown, [number]>("DELETE FROM conversations WHERE attempt_at < ?").run(before)
    .changes;
}

export function emailSummary(db: Database, id: string, now: number) {
  const msg = db
    .query<{ id: string; metadata: string; created_at: number }, [string]>(
      "SELECT id, metadata, created_at FROM messages WHERE id = ? AND type = 'email'",
    )
    .get(id);
  if (!msg) return null;
  const meta = JSON.parse(msg.metadata) as Partial<EmailMeta>;
  const scheduled = (meta.scheduledAt ?? 0) > now;
  const recipients = recipientsOf(db, id).map((r) => ({
    email: r.address,
    status: recipientStatus(r.status, r.class, scheduled),
  }));
  return {
    object: "email",
    id: msg.id,
    from: meta.from ?? null,
    to: meta.to ?? [],
    tags: meta.tags ?? [],
    lane: meta.lane ?? "transactional",
    created_at: iso(msg.created_at),
    last_event: emailStatus(recipients.map((r) => r.status)),
    recipients,
  };
}
