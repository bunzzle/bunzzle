import type { Database } from "bun:sqlite";
import type { ProjectId } from "./projects.ts";

const MINUTE = 60_000;
const HOUR = 3_600_000;

export type LimitWindow = "hour" | "day";

export interface Limits {
  perHour: number | null;
  perDay: number | null;
}

export interface Over {
  window: LimitWindow;
  limit: number;
  used: number;
  retryAfterMs: number | null;
}

export interface Near {
  window: LimitWindow;
  limit: number;
  used: number;
}

const WINDOWS = [
  { window: "hour", unit: "minute", size: MINUTE, slots: 60 },
  { window: "day", unit: "hour", size: HOUR, slots: 24 },
] as const;

const limitOf = (l: Limits, w: LimitWindow) => (w === "hour" ? l.perHour : l.perDay);

export function takeQuota(
  db: Database,
  project: ProjectId,
  limits: Limits,
  n: number,
  now: number,
): { ok: true; near: Near[] } | { ok: false; over: Over } {
  if (n <= 0 || (limits.perHour === null && limits.perDay === null)) return { ok: true, near: [] };
  const sum = db.query<{ n: number }, [string, string, number]>(
    "SELECT coalesce(sum(n), 0) AS n FROM project_usage WHERE project_id = ? AND unit = ? AND slot > ?",
  );
  const slots = db.query<{ slot: number; n: number }, [string, string, number]>(
    "SELECT slot, n FROM project_usage WHERE project_id = ? AND unit = ? AND slot > ? ORDER BY slot",
  );
  const used = new Map<LimitWindow, number>();
  for (const w of WINDOWS) {
    const limit = limitOf(limits, w.window);
    if (limit === null) continue;
    const current = Math.floor(now / w.size);
    const total = sum.get(project, w.unit, current - w.slots)?.n ?? 0;
    used.set(w.window, total);
    if (total + n <= limit) continue;
    if (n > limit)
      return { ok: false, over: { window: w.window, limit, used: total, retryAfterMs: null } };
    const overflow = total + n - limit;
    let freed = 0;
    let retryAfterMs = w.slots * w.size;
    for (const r of slots.all(project, w.unit, current - w.slots)) {
      freed += r.n;
      if (freed >= overflow) {
        retryAfterMs = (r.slot + w.slots) * w.size - now;
        break;
      }
    }
    return {
      ok: false,
      over: { window: w.window, limit, used: total, retryAfterMs: Math.max(1_000, retryAfterMs) },
    };
  }
  const add = db.query<unknown, [string, string, number, number]>(
    `INSERT INTO project_usage (project_id, unit, slot, n) VALUES (?, ?, ?, ?)
     ON CONFLICT (project_id, unit, slot) DO UPDATE SET n = n + excluded.n`,
  );
  for (const w of WINDOWS) add.run(project, w.unit, Math.floor(now / w.size), n);
  const near: Near[] = [];
  const notice = db.query<unknown, [string, string, number, number]>(
    `INSERT INTO project_limit_notices (project_id, span, notified_at) VALUES (?1, ?2, ?3)
     ON CONFLICT (project_id, span) DO UPDATE SET notified_at = excluded.notified_at
     WHERE notified_at <= ?3 - ?4`,
  );
  for (const w of WINDOWS) {
    const limit = limitOf(limits, w.window);
    const before = used.get(w.window);
    if (limit === null || before === undefined) continue;
    const after = before + n;
    if (after < limit * 0.9) continue;
    if (notice.run(project, w.window, now, w.slots * w.size).changes > 0) {
      near.push({ window: w.window, limit, used: after });
    }
  }
  return { ok: true, near };
}

export function pruneUsage(db: Database, now: number): void {
  for (const w of WINDOWS) {
    db.query<unknown, [string, number]>(
      "DELETE FROM project_usage WHERE unit = ? AND slot <= ?",
    ).run(w.unit, Math.floor(now / w.size) - w.slots);
  }
}
