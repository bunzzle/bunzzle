import type { Database } from "bun:sqlite";
import { appendEvent } from "../core/events.ts";
import { b } from "../validate/schema.ts";

export const MAX_EVENTS = 100;

const trackingSchema = b.object({
  host: b.string(),
  opens: b.boolean(),
  clicks: b.boolean(),
  status: b.enum(["pending", "verified", "missing", "mismatch"]),
  found: b.string().nullable(),
  checkedAt: b.number().nullable(),
});

export type Tracking = b.infer<typeof trackingSchema>;

export function getTracking(db: Database, domain: string): Tracking | null {
  const r = db
    .query<{ tracking: string | null }, [string]>("SELECT tracking FROM domains WHERE name = ?")
    .get(domain);
  return r?.tracking ? trackingSchema.parse(JSON.parse(r.tracking)) : null;
}

export function setTracking(
  db: Database,
  domain: string,
  t: Tracking | null,
  now: number,
): boolean {
  return (
    db
      .query<unknown, [string | null, number, string]>(
        "UPDATE domains SET tracking = ?, updated_at = ? WHERE name = ?",
      )
      .run(t ? JSON.stringify(t) : null, now, domain).changes > 0
  );
}

export function listTracking(db: Database): { domain: string; tracking: Tracking }[] {
  return db
    .query<{ name: string; tracking: string }, []>(
      "SELECT name, tracking FROM domains WHERE tracking IS NOT NULL ORDER BY name",
    )
    .all()
    .map((r) => ({ domain: r.name, tracking: trackingSchema.parse(JSON.parse(r.tracking)) }));
}

export function checkTracking(t: Tracking, found: string[], target: string, now: number): Tracking {
  const want = target.toLowerCase();
  const names = found.map((n) => n.toLowerCase().replace(/\.$/, ""));
  const status = names.length === 0 ? "missing" : names.includes(want) ? "verified" : "mismatch";
  return { ...t, status, found: names[0] ?? null, checkedAt: now };
}

export function trackingView(t: Tracking | null, target: string | null) {
  if (!t) return null;
  return {
    host: t.host,
    opens: t.opens,
    clicks: t.clicks,
    record: {
      name: t.host,
      type: "CNAME",
      value: target,
      status: t.status,
      found: t.found,
    },
    checked_at: t.checkedAt === null ? null : new Date(t.checkedAt).toISOString(),
  };
}

export function recordTrack(
  db: Database,
  messageId: string,
  kind: "opened" | "clicked",
  data: Record<string, unknown>,
  now: number,
): boolean {
  const seen =
    db
      .query<{ n: number }, [string, string]>(
        "SELECT count(*) AS n FROM events WHERE message_id = ? AND kind = ?",
      )
      .get(messageId, kind)?.n ?? 0;
  if (seen >= MAX_EVENTS) return false;
  appendEvent(db, { messageId, kind, data, source: "tracking", at: now });
  return true;
}
