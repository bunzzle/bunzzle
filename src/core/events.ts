import type { Database } from "bun:sqlite";

export interface EventInput {
  messageId: string;
  kind: string;
  data?: Record<string, unknown>;
  source: string;
  at: number;
}

export function appendEvent(db: Database, e: EventInput): void {
  db.query<unknown, [string, string, string | null, string, number]>(
    "INSERT INTO events (message_id, kind, data, source, occurred_at) VALUES (?, ?, ?, ?, ?)",
  ).run(e.messageId, e.kind, e.data ? JSON.stringify(e.data) : null, e.source, e.at);
}

export interface StoredEvent {
  id: number;
  kind: string;
  data: Record<string, unknown> | null;
  source: string;
  occurred_at: number;
}

export function eventsFor(db: Database, messageId: string): StoredEvent[] {
  return db
    .query<
      { id: number; kind: string; data: string | null; source: string; occurred_at: number },
      [string]
    >("SELECT id, kind, data, source, occurred_at FROM events WHERE message_id = ? ORDER BY id")
    .all(messageId)
    .map((r) => ({ ...r, data: r.data === null ? null : JSON.parse(r.data) }));
}
