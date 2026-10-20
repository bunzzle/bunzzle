import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { DayStats } from "../net/postmaster.ts";
import { createHold, type Hold } from "./guards.ts";

const SPAM_LIMIT = 0.003;
const SPAM_WARN = 0.001;

export function savePostmaster(db: Database, domain: string, days: DayStats[], now: number) {
  const put = db.query<unknown, [string, string, number | null, string | null, string, number]>(
    `INSERT INTO postmaster_stats (domain, day, spam_ratio, reputation, data, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (domain, day) DO UPDATE SET spam_ratio = excluded.spam_ratio,
       reputation = excluded.reputation, data = excluded.data, fetched_at = excluded.fetched_at`,
  );
  for (const d of days) put.run(domain, d.day, d.spamRatio, d.reputation, JSON.stringify(d), now);
}

export function latestPostmaster(db: Database, domain: string): DayStats | null {
  const r = db
    .query<{ data: string }, [string]>(
      "SELECT data FROM postmaster_stats WHERE domain = ? ORDER BY day DESC LIMIT 1",
    )
    .get(domain);
  return r ? (JSON.parse(r.data) as DayStats) : null;
}

const percent = (r: number) => `${(r * 100).toFixed(2)}%`;

export function gmailGuard(db: Database, domains: string[], now: number, log: Logger): Hold[] {
  const made: Hold[] = [];
  for (const domain of domains) {
    const s = latestPostmaster(db, domain);
    if (!s) continue;
    let reason: string | null = null;
    if (s.spamRatio !== null && s.spamRatio >= SPAM_LIMIT) {
      reason = `Gmail reports a spam rate of ${percent(s.spamRatio)} for ${s.day} (its limit is 0.3%)`;
    } else if (s.reputation === "BAD") {
      reason = `Gmail rates the domain reputation BAD for ${s.day}`;
    } else if ((s.spamRatio ?? 0) >= SPAM_WARN || s.reputation === "LOW") {
      log.warn("Gmail reputation is slipping for a sending domain", {
        domain,
        day: s.day,
        spam_rate: s.spamRatio === null ? null : percent(s.spamRatio),
        reputation: s.reputation,
      });
    }
    if (!reason) continue;
    const { hold, created } = createHold(db, `domain:${domain}`, "bulk", reason, now);
    if (created) {
      log.error("bulk mail paused for a sending domain", { domain, reason });
      made.push(hold);
    }
  }
  return made;
}
