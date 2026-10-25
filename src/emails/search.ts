import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";

export const METRICS = [
  "sent",
  "delivered",
  "deferred",
  "bounced",
  "failed",
  "suppressed",
  "complained",
  "unsubscribed",
] as const;

export type Metric = (typeof METRICS)[number];

const tagKey = (t: { name: string; value: string }) => `${t.name}:${t.value}`;
const dayOf = (at: number) => new Date(at).toISOString().slice(0, 10);
const SEP = "\u0000";
const held = new WeakMap<Database, Map<string, number>>();

const upsertStat = (db: Database) =>
  db.query<unknown, [string, string, string, string, string, number]>(
    `INSERT INTO stats_daily (project_id, day, domain, tag, metric, n) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (project_id, day, domain, tag, metric) DO UPDATE SET n = n + excluded.n`,
  );

export function holdStats(db: Database): void {
  if (!held.has(db)) held.set(db, new Map());
}

export function flushStats(db: Database): void {
  const pending = held.get(db);
  if (!pending || pending.size === 0) return;
  const add = upsertStat(db);
  for (const [key, n] of pending) {
    const [project, day, domain, tag, metric] = key.split(SEP) as [
      string,
      string,
      string,
      string,
      string,
    ];
    add.run(project, day, domain, tag, metric, n);
  }
  pending.clear();
}

export function indexEmail(
  db: Database,
  e: {
    id: string;
    project: ProjectId;
    domain: string;
    keyId: string | null;
    test: boolean;
    tags: { name: string; value: string }[];
  },
): void {
  db.query<unknown, [string, string, string, string | null, number]>(
    "INSERT OR IGNORE INTO email_index (message_id, project_id, domain, key_id, test) VALUES (?, ?, ?, ?, ?)",
  ).run(e.id, e.project, e.domain, e.keyId, e.test ? 1 : 0);
  if (e.tags.length === 0) return;
  db.query<unknown, string[]>(
    `INSERT OR IGNORE INTO email_tags (message_id, tag) VALUES ${e.tags.map(() => "(?, ?)").join(", ")}`,
  ).run(...e.tags.flatMap((t) => [e.id, tagKey(t)]));
}

export function countEmail(
  db: Database,
  messageId: string,
  metric: Metric,
  n: number,
  at: number,
): void {
  if (n <= 0) return;
  const e = db
    .query<{ project_id: string; domain: string; test: number }, [string]>(
      "SELECT project_id, domain, test FROM email_index WHERE message_id = ?",
    )
    .get(messageId);
  if (!e || e.test === 1) return;
  const tags = db
    .query<{ tag: string }, [string]>("SELECT tag FROM email_tags WHERE message_id = ?")
    .all(messageId)
    .map((r) => r.tag);
  const day = dayOf(at);
  const pending = held.get(db);
  if (pending) {
    for (const tag of ["", ...tags]) {
      const key = [e.project_id, day, e.domain, tag, metric].join(SEP);
      pending.set(key, (pending.get(key) ?? 0) + n);
    }
    return;
  }
  const add = upsertStat(db);
  for (const tag of ["", ...tags]) add.run(e.project_id, day, e.domain, tag, metric, n);
}

export interface StatsQuery {
  since: string;
  until: string;
  domain?: string | undefined;
  tag?: string | undefined;
}

export type DayCounts = { day: string } & Record<Metric, number>;

export function statsFor(db: Database, project: ProjectId, q: StatsQuery): DayCounts[] {
  const rows = db
    .query<
      { day: string; metric: Metric; n: number },
      [string, string, string, string, string | null]
    >(
      `SELECT day, metric, sum(n) AS n FROM stats_daily
       WHERE project_id = ?1 AND day >= ?2 AND day <= ?3 AND tag = ?4 AND (?5 IS NULL OR domain = ?5)
       GROUP BY day, metric ORDER BY day`,
    )
    .all(project, q.since, q.until, q.tag ?? "", q.domain ?? null);
  const byDay = new Map<string, DayCounts>();
  for (let t = Date.parse(q.since); t <= Date.parse(q.until); t += 86_400_000) {
    const day = dayOf(t);
    byDay.set(day, Object.assign({ day }, ...METRICS.map((m) => ({ [m]: 0 }))) as DayCounts);
  }
  for (const r of rows) {
    const d = byDay.get(r.day);
    if (d) d[r.metric] = r.n;
  }
  for (const [key, n] of held.get(db) ?? []) {
    const [p, day, domain, tag, metric] = key.split(SEP) as [
      string,
      string,
      string,
      string,
      Metric,
    ];
    if (p !== project || tag !== (q.tag ?? "") || (q.domain !== undefined && domain !== q.domain)) {
      continue;
    }
    const d = byDay.get(day);
    if (d) d[metric] += n;
  }
  return [...byDay.values()];
}

export interface SearchQuery {
  to?: string | undefined;
  status?: string | undefined;
  tag?: string | undefined;
  domain?: string | undefined;
  since?: number | undefined;
  until?: number | undefined;
  before?: string | undefined;
  limit: number;
}

export function idAt(ms: number, high: boolean): string {
  const hex = Math.max(0, Math.floor(ms)).toString(16).padStart(12, "0").slice(-12);
  const tail = high ? "ffff-ffff-ffff-ffffffffffff" : "0000-0000-0000-000000000000";
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${tail}`;
}

export function searchEmails(db: Database, project: ProjectId, q: SearchQuery): string[] {
  const where: string[] = ["m.type = 'email'", "x.project_id = ?"];
  const args: (string | number)[] = [project];
  if (q.before !== undefined) {
    where.push("x.message_id < ?");
    args.push(q.before);
  }
  if (q.since !== undefined) {
    where.push("x.message_id >= ?");
    args.push(idAt(q.since, false));
  }
  if (q.until !== undefined) {
    where.push("x.message_id <= ?");
    args.push(idAt(q.until, true));
  }
  if (q.to !== undefined) {
    where.push(
      "EXISTS (SELECT 1 FROM recipients r JOIN jobs j ON j.id = r.job_id WHERE j.message_id = m.id AND r.address = ?)",
    );
    args.push(q.to);
  }
  if (q.status !== undefined) {
    where.push(
      "EXISTS (SELECT 1 FROM recipients r JOIN jobs j ON j.id = r.job_id WHERE j.message_id = m.id AND r.status = ?)",
    );
    args.push(q.status);
  }
  if (q.tag !== undefined) {
    where.push("EXISTS (SELECT 1 FROM email_tags t WHERE t.message_id = m.id AND t.tag = ?)");
    args.push(q.tag);
  }
  if (q.domain !== undefined) {
    where.push("x.domain = ?");
    args.push(q.domain);
  }
  const source =
    q.to !== undefined
      ? `(SELECT DISTINCT j.message_id AS id FROM recipients r JOIN jobs j ON j.id = r.job_id WHERE r.address = ?)`
      : q.tag !== undefined
        ? "(SELECT message_id AS id FROM email_tags WHERE tag = ?)"
        : q.status !== undefined && q.status !== "delivered"
          ? "(SELECT DISTINCT j.message_id AS id FROM recipients r JOIN jobs j ON j.id = r.job_id WHERE r.status = ? AND r.status <> 'delivered')"
          : null;
  const driver = q.to ?? q.tag ?? (q.status !== "delivered" ? q.status : undefined);
  const sql = source
    ? `SELECT m.id FROM ${source} c JOIN email_index x ON x.message_id = c.id JOIN messages m ON m.id = c.id WHERE ${where.join(" AND ")} ORDER BY m.id DESC LIMIT ?`
    : `SELECT m.id FROM email_index x JOIN messages m ON m.id = x.message_id WHERE ${where.join(" AND ")} ORDER BY x.message_id DESC LIMIT ?`;
  const params = [...(source && driver !== undefined ? [driver] : []), ...args, q.limit];
  return db
    .query<{ id: string }, (string | number)[]>(sql)
    .all(...params)
    .map((r) => r.id);
}
