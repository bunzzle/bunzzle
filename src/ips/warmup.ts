import type { Database } from "bun:sqlite";
import type { SourceIp } from "../config.ts";
import type { Logger } from "../core/log.ts";

export const DAY_MS = 86_400_000;
export const DONE_BUDGET = 50_000;
const KNOWN = new Set(["google", "microsoft", "yahoo", "apple"]);

export const dayOf = (t: number) => Math.floor(t / DAY_MS);
export const bucketOf = (provider: string | null) =>
  provider && KNOWN.has(provider) ? provider : "other";
export const startBudget = (bucket: string) => (bucket === "other" ? 100 : 50);

export type Health = "healthy" | "borderline" | "bad" | "quiet";

export interface Counters {
  sent: number;
  delivered: number;
  deferred: number;
  bounced: number;
  blocked: number;
  complained: number;
}

export interface WarmupRow extends Counters {
  ip: string;
  provider: string;
  startedDay: number;
  day: number;
  budget: number;
  state: "warming" | "done";
  history: { day: number; budget: number; sent: number; health: Health }[];
}

export function health(c: Counters, budget: number): Health {
  if (c.blocked > 0) return "bad";
  const base = Math.max(1, c.sent);
  const complaints = c.complained / Math.max(1, c.delivered);
  if (complaints >= 0.003 || c.bounced / base >= 0.1 || c.deferred / base >= 0.3) return "bad";
  if (complaints >= 0.001 || c.bounced / base >= 0.05 || c.deferred / base >= 0.1)
    return "borderline";
  if (c.sent < budget / 2) return "quiet";
  return "healthy";
}

export function nextBudget(
  row: Pick<WarmupRow, "budget" | "day" | "startedDay" | "provider">,
  h: Health,
): number {
  const days = row.day - row.startedDay + 1;
  const floor = startBudget(row.provider);
  switch (h) {
    case "healthy":
      return Math.round(row.budget * (days <= 7 ? 2 : 1.5));
    case "bad":
      return Math.max(floor, Math.round(row.budget / 2));
    default:
      return row.budget;
  }
}

export function estimatedDays(budget: number, daysSoFar: number): number {
  let b = budget;
  let d = daysSoFar;
  while (b < DONE_BUDGET && d < 365) {
    b *= d <= 7 ? 2 : 1.5;
    d++;
  }
  return d;
}

interface Row {
  ip: string;
  provider: string;
  started_day: number;
  day: number;
  budget: number;
  sent: number;
  delivered: number;
  deferred: number;
  bounced: number;
  blocked: number;
  complained: number;
  state: "warming" | "done";
  history: string;
}

const fromRow = (r: Row): WarmupRow => ({
  ip: r.ip,
  provider: r.provider,
  startedDay: r.started_day,
  day: r.day,
  budget: r.budget,
  sent: r.sent,
  delivered: r.delivered,
  deferred: r.deferred,
  bounced: r.bounced,
  blocked: r.blocked,
  complained: r.complained,
  state: r.state,
  history: JSON.parse(r.history),
});

export function getWarmup(db: Database, ip: string, bucket: string): WarmupRow | null {
  const r = db
    .query<Row, [string, string]>("SELECT * FROM warmup WHERE ip = ? AND provider = ?")
    .get(ip, bucket);
  return r ? fromRow(r) : null;
}

export function listWarmup(db: Database): WarmupRow[] {
  return db.query<Row, []>("SELECT * FROM warmup ORDER BY ip, provider").all().map(fromRow);
}

export function countWarmup(
  db: Database,
  ip: string,
  bucket: string,
  delta: Partial<Counters>,
  now: number,
): void {
  const today = dayOf(now);
  db.query<unknown, [string, string, number, number, number, number]>(
    `INSERT INTO warmup (ip, provider, started_day, day, budget, state, updated_at)
     VALUES (?, ?, ?, ?, ?, 'warming', ?) ON CONFLICT (ip, provider) DO NOTHING`,
  ).run(ip, bucket, today, today, startBudget(bucket), now);
  db.query<unknown, [number, number, number, number, number, number, number, string, string]>(
    `UPDATE warmup SET sent = sent + ?, delivered = delivered + ?, deferred = deferred + ?,
       bounced = bounced + ?, blocked = blocked + ?, complained = complained + ?, updated_at = ?
     WHERE ip = ? AND provider = ?`,
  ).run(
    delta.sent ?? 0,
    delta.delivered ?? 0,
    delta.deferred ?? 0,
    delta.bounced ?? 0,
    delta.blocked ?? 0,
    delta.complained ?? 0,
    now,
    ip,
    bucket,
  );
}

export function rollover(db: Database, now: number, log: Logger): number {
  const today = dayOf(now);
  const due = db
    .query<Row, [number]>("SELECT * FROM warmup WHERE day < ? AND state = 'warming'")
    .all(today)
    .map(fromRow);
  for (const row of due) {
    const h = health(row, row.budget);
    const budget = nextBudget(row, h);
    const history = [
      ...row.history,
      { day: row.day, budget: row.budget, sent: row.sent, health: h },
    ].slice(-60);
    const state = budget >= DONE_BUDGET ? "done" : "warming";
    db.query<unknown, [number, number, string, string, number, string, string]>(
      `UPDATE warmup SET day = ?, budget = ?, state = ?, history = ?, sent = 0, delivered = 0,
         deferred = 0, bounced = 0, blocked = 0, complained = 0, updated_at = ?
       WHERE ip = ? AND provider = ?`,
    ).run(today, budget, state, JSON.stringify(history), now, row.ip, row.provider);
    const fields = { ip: row.ip, provider: row.provider, health: h, budget };
    if (h === "bad")
      log.error("warm-up stepped back: this IP had trouble at this provider", fields);
    else if (state === "done") log.info("warm-up finished", fields);
    else log.info("warm-up day evaluated", fields);
  }
  return due.length;
}

export interface Choice {
  source: string;
}

export interface Wait {
  wait: { delayMs: number; reason: string };
}

export function choose(
  db: Database,
  ips: SourceIp[],
  lane: "transactional" | "bulk",
  target: string,
  provider: string | null,
  recipients: number,
  now: number,
  pausedUntil: (ip: string) => number | null,
): Choice | Wait {
  if (ips.length === 0) return { source: "default" };
  const pool = (name: string) => ips.filter((x) => x.pool === name);
  const candidates =
    lane === "bulk"
      ? pool("bulk").length
        ? pool("bulk")
        : pool("main").length
          ? pool("main")
          : ips
      : pool("main").length
        ? pool("main")
        : ips;
  const ordered = [...candidates].sort(
    (a, b) => rank(b.ip, target) - rank(a.ip, target) || a.ip.localeCompare(b.ip),
  );
  const bucket = bucketOf(provider);
  let soonestPause: number | null = null;
  let overBudget: { ip: string; budget: number; day: number } | null = null;
  for (const ip of ordered) {
    const paused = pausedUntil(ip.ip);
    if (paused !== null) {
      soonestPause = soonestPause === null ? paused : Math.min(soonestPause, paused);
      continue;
    }
    if (!ip.established) {
      const w = getWarmup(db, ip.ip, bucket);
      const today = dayOf(now);
      const budget = w && w.day === today ? w.budget : w ? w.budget : startBudget(bucket);
      const sent = w && w.day === today ? w.sent : 0;
      if ((w?.state ?? "warming") === "warming" && sent + recipients > budget) {
        overBudget ??= { ip: ip.ip, budget, day: (w ? today - w.startedDay : 0) + 1 };
        continue;
      }
    }
    return { source: ip.ip };
  }
  if (overBudget) {
    const tomorrow = (dayOf(now) + 1) * DAY_MS;
    return {
      wait: {
        delayMs: Math.max(60_000, tomorrow - now + 60_000),
        reason: `warm-up: today's ${bucket} budget for ${overBudget.ip} (day ${overBudget.day}, ${overBudget.budget}) is used up`,
      },
    };
  }
  return {
    wait: {
      delayMs: Math.max(1_000, (soonestPause ?? now + 60_000) - now),
      reason: `every source IP is paused for ${target}`,
    },
  };
}

function rank(ip: string, target: string): number {
  let h = 2166136261;
  for (const ch of `${ip}|${target}`) {
    h ^= ch.charCodeAt(0);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h;
}
