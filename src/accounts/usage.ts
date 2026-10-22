import type { Database } from "bun:sqlite";
import type { ProjectId } from "./projects.ts";

const MINUTE = 60_000;
const HOUR = 3_600_000;

export type LimitWindow = "hour" | "day";

export type LimitSetting = "per_hour" | "per_day" | "new_recipients_per_day";

export interface Limits {
  perHour: number | null;
  perDay: number | null;
  newPerDay: number | null;
}

export interface Over {
  setting: LimitSetting;
  window: LimitWindow;
  limit: number;
  used: number;
  retryAfterMs: number | null;
}

export interface Near {
  setting: LimitSetting;
  window: LimitWindow;
  limit: number;
  used: number;
}

const WINDOWS = [
  { setting: "per_hour", window: "hour", span: "hour", unit: "minute", size: MINUTE, slots: 60 },
  { setting: "per_day", window: "day", span: "day", unit: "hour", size: HOUR, slots: 24 },
  {
    setting: "new_recipients_per_day",
    window: "day",
    span: "new",
    unit: "new_hour",
    size: HOUR,
    slots: 24,
  },
] as const;

type Window = (typeof WINDOWS)[number];

const limitOf = (l: Limits, w: Window) =>
  w.setting === "per_hour" ? l.perHour : w.setting === "per_day" ? l.perDay : l.newPerDay;

const countOf = (w: Window, n: number, fresh: number) =>
  w.setting === "new_recipients_per_day" ? fresh : n;

export function takeQuota(
  db: Database,
  project: ProjectId,
  limits: Limits,
  n: number,
  fresh: number,
  now: number,
): { ok: true; near: Near[] } | { ok: false; over: Over } {
  if (n <= 0 || (limits.perHour === null && limits.perDay === null && limits.newPerDay === null))
    return { ok: true, near: [] };
  const sum = db.query<{ n: number }, [string, string, number]>(
    "SELECT coalesce(sum(n), 0) AS n FROM project_usage WHERE project_id = ? AND unit = ? AND slot > ?",
  );
  const slots = db.query<{ slot: number; n: number }, [string, string, number]>(
    "SELECT slot, n FROM project_usage WHERE project_id = ? AND unit = ? AND slot > ? ORDER BY slot",
  );
  const used = new Map<LimitSetting, number>();
  for (const w of WINDOWS) {
    const limit = limitOf(limits, w);
    if (limit === null) continue;
    const count = countOf(w, n, fresh);
    const current = Math.floor(now / w.size);
    const total = sum.get(project, w.unit, current - w.slots)?.n ?? 0;
    used.set(w.setting, total);
    if (total + count <= limit) continue;
    const over = { setting: w.setting, window: w.window, limit, used: total };
    if (count > limit) return { ok: false, over: { ...over, retryAfterMs: null } };
    const overflow = total + count - limit;
    let freed = 0;
    let retryAfterMs = w.slots * w.size;
    for (const r of slots.all(project, w.unit, current - w.slots)) {
      freed += r.n;
      if (freed >= overflow) {
        retryAfterMs = (r.slot + w.slots) * w.size - now;
        break;
      }
    }
    return { ok: false, over: { ...over, retryAfterMs: Math.max(1_000, retryAfterMs) } };
  }
  const add = db.query<unknown, [string, string, number, number]>(
    `INSERT INTO project_usage (project_id, unit, slot, n) VALUES (?, ?, ?, ?)
     ON CONFLICT (project_id, unit, slot) DO UPDATE SET n = n + excluded.n`,
  );
  for (const w of WINDOWS) {
    const count = countOf(w, n, fresh);
    if (count > 0) add.run(project, w.unit, Math.floor(now / w.size), count);
  }
  const near: Near[] = [];
  const notice = db.query<unknown, [string, string, number, number]>(
    `INSERT INTO project_limit_notices (project_id, span, notified_at) VALUES (?1, ?2, ?3)
     ON CONFLICT (project_id, span) DO UPDATE SET notified_at = excluded.notified_at
     WHERE notified_at <= ?3 - ?4`,
  );
  for (const w of WINDOWS) {
    const limit = limitOf(limits, w);
    const before = used.get(w.setting);
    if (limit === null || before === undefined) continue;
    const after = before + countOf(w, n, fresh);
    if (after < limit * 0.9) continue;
    if (notice.run(project, w.span, now, w.slots * w.size).changes > 0) {
      near.push({ setting: w.setting, window: w.window, limit, used: after });
    }
  }
  return { ok: true, near };
}

export function noteLimitReached(
  db: Database,
  project: ProjectId,
  setting: LimitSetting,
  now: number,
): boolean {
  const w = WINDOWS.find((x) => x.setting === setting);
  if (!w) return false;
  return (
    db
      .query<unknown, [string, string, number, number]>(
        `INSERT INTO project_limit_notices (project_id, span, notified_at) VALUES (?1, ?2, ?3)
         ON CONFLICT (project_id, span) DO UPDATE SET notified_at = excluded.notified_at
         WHERE notified_at <= ?3 - ?4`,
      )
      .run(project, `${w.span}:reached`, now, w.slots * w.size).changes > 0
  );
}

export function pruneUsage(db: Database, now: number): void {
  for (const w of WINDOWS) {
    db.query<unknown, [string, number]>(
      "DELETE FROM project_usage WHERE unit = ? AND slot <= ?",
    ).run(w.unit, Math.floor(now / w.size) - w.slots);
  }
}
