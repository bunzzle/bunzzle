import type { Database } from "bun:sqlite";
import type { EventType } from "./store.ts";
import { listWebhooks } from "./store.ts";

const CURSOR = "webhook_cursor";

interface EventRow {
  id: number;
  message_id: string;
  kind: string;
  data: string | null;
  occurred_at: number;
}

function typeOf(kind: string, data: Record<string, unknown>): EventType | null {
  switch (kind) {
    case "recipient":
      if (data["status"] === "delivered") return "email.delivered";
      if (data["status"] === "bounced") return "email.bounced";
      return null;
    case "bounced":
      return "email.bounced";
    case "delayed":
      return "email.delivery_delayed";
    case "complained":
      return "email.complained";
    case "unsubscribed":
      return "email.unsubscribed";
    case "suppressed":
      return "email.suppressed";
    case "dead":
      return data["code"] === "expired" || data["code"] === "retries_exhausted"
        ? "email.failed"
        : null;
    default:
      return null;
  }
}

function meta(db: Database, messageId: string) {
  const r = db
    .query<{ metadata: string; created_at: number }, [string]>(
      "SELECT metadata, created_at FROM messages WHERE id = ?",
    )
    .get(messageId);
  const m = r ? (JSON.parse(r.metadata) as Record<string, unknown>) : {};
  return {
    from: m["from"] ?? null,
    to: m["to"] ?? [],
    tags: m["tags"] ?? [],
    lane: m["lane"] ?? "transactional",
    created_at: r ? new Date(r.created_at).toISOString() : null,
  };
}

export function projectEvents(db: Database, now: number, limit = 500): number {
  const cursor = Number(
    db.query<{ value: string }, [string]>("SELECT value FROM settings WHERE key = ?").get(CURSOR)
      ?.value ?? 0,
  );
  const rows = db
    .query<EventRow, [number, number]>(
      "SELECT id, message_id, kind, data, occurred_at FROM events WHERE id > ? ORDER BY id LIMIT ?",
    )
    .all(cursor, limit);
  if (rows.length === 0) return 0;
  const hooks = listWebhooks(db);
  const insert = db.query<unknown, [string, string, string, string, number, number, number]>(
    `INSERT INTO webhook_deliveries (id, webhook_id, type, payload, state, next_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`,
  );
  let made = 0;
  for (const e of rows) {
    if (hooks.length === 0) break;
    const data = e.data ? (JSON.parse(e.data) as Record<string, unknown>) : {};
    const type = typeOf(e.kind, data);
    if (!type) continue;
    const targets = hooks.filter((h) => h.events.includes(type));
    if (targets.length === 0) continue;
    const m = meta(db, e.message_id);
    const detail: Record<string, unknown> = {
      email_id: e.message_id,
      created_at: m.created_at,
      from: m.from,
      to: m.to,
      subject: null,
      tags: m.tags,
      lane: m.lane,
    };
    if (typeof data["address"] === "string") detail["recipient"] = data["address"];
    if (type === "email.bounced") {
      detail["bounce"] = {
        type: "Permanent",
        class: data["class"] ?? null,
        about: data["about"] ?? data["scope"] ?? null,
        message: data["reply"] ?? null,
        async: data["async"] === true,
      };
    }
    if (type === "email.delivery_delayed") detail["reason"] = data["reason"] ?? null;
    if (type === "email.suppressed") {
      detail["suppression"] = { reason: data["reason"] ?? null, scope: data["scope"] ?? null };
    }
    if (type === "email.complained") detail["feedback_type"] = data["feedback_type"] ?? null;
    if (type === "email.failed") detail["reason"] = data["code"] ?? null;
    const payload = JSON.stringify({
      type,
      created_at: new Date(e.occurred_at).toISOString(),
      data: detail,
    });
    for (const h of targets) {
      insert.run(Bun.randomUUIDv7(), h.id, type, payload, now, now, now);
      made++;
    }
  }
  const last = (rows.at(-1) as EventRow).id;
  db.query<unknown, [string, string, number]>(
    `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
  ).run(CURSOR, String(last), now);
  return made;
}
