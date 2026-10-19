import type { Database } from "bun:sqlite";
import type { DmarcReport } from "./report.ts";

const DAY = 86_400_000;

export function saveDmarcReport(db: Database, r: DmarcReport, now: number): boolean {
  const row = db
    .query<{ id: number }, [string, string, string | null, string, string, number, number, number]>(
      `INSERT INTO dmarc_reports (org, report_id, email, domain, policy, begin_at, end_at, received_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (org, report_id) DO NOTHING RETURNING id`,
    )
    .get(r.org, r.reportId, r.email, r.domain, r.policy, r.begin, r.end, now);
  if (!row) return false;
  const insert = db.query<
    unknown,
    [number, string, number, string, string, string, string, string | null, string, string | null]
  >(
    `INSERT INTO dmarc_rows (report, source_ip, count, disposition, dkim, spf, header_from,
       envelope_from, dkim_domains, spf_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (const x of r.rows) {
    insert.run(
      row.id,
      x.sourceIp,
      x.count,
      x.disposition,
      x.dkim,
      x.spf,
      x.headerFrom,
      x.envelopeFrom,
      JSON.stringify(x.dkimDomains),
      x.spfDomain,
    );
  }
  return true;
}

export function pruneDmarc(db: Database, now: number, keepMs = 90 * DAY): number {
  return db.query<unknown, [number]>("DELETE FROM dmarc_reports WHERE end_at < ?").run(now - keepMs)
    .changes;
}

export interface DmarcSource {
  source_ip: string;
  messages: number;
  dkim_pass: number;
  spf_pass: number;
  dmarc_pass: number;
  dispositions: Record<string, number>;
}

export interface DmarcDay {
  day: string;
  messages: number;
  dmarc_pass: number;
  dkim_pass: number;
  spf_pass: number;
  reporters: string[];
  sources: DmarcSource[];
}

export function dmarcSummary(db: Database, domain: string, days: number, now: number): DmarcDay[] {
  const rows = db
    .query<
      {
        begin_at: number;
        org: string;
        source_ip: string;
        count: number;
        disposition: string;
        dkim: string;
        spf: string;
      },
      [string, number]
    >(
      `SELECT r.begin_at, r.org, x.source_ip, x.count, x.disposition, x.dkim, x.spf
       FROM dmarc_reports r JOIN dmarc_rows x ON x.report = r.id
       WHERE r.domain = ? AND r.end_at >= ? ORDER BY r.begin_at`,
    )
    .all(domain, now - days * DAY);
  const byDay = new Map<
    string,
    DmarcDay & { orgs: Set<string>; bySource: Map<string, DmarcSource> }
  >();
  for (const x of rows) {
    const day = new Date(x.begin_at).toISOString().slice(0, 10);
    let d = byDay.get(day);
    if (!d) {
      d = {
        day,
        messages: 0,
        dmarc_pass: 0,
        dkim_pass: 0,
        spf_pass: 0,
        reporters: [],
        sources: [],
        orgs: new Set(),
        bySource: new Map(),
      };
      byDay.set(day, d);
    }
    const dkim = x.dkim === "pass";
    const spf = x.spf === "pass";
    d.orgs.add(x.org);
    d.messages += x.count;
    if (dkim) d.dkim_pass += x.count;
    if (spf) d.spf_pass += x.count;
    if (dkim || spf) d.dmarc_pass += x.count;
    let s = d.bySource.get(x.source_ip);
    if (!s) {
      s = {
        source_ip: x.source_ip,
        messages: 0,
        dkim_pass: 0,
        spf_pass: 0,
        dmarc_pass: 0,
        dispositions: {},
      };
      d.bySource.set(x.source_ip, s);
    }
    s.messages += x.count;
    if (dkim) s.dkim_pass += x.count;
    if (spf) s.spf_pass += x.count;
    if (dkim || spf) s.dmarc_pass += x.count;
    s.dispositions[x.disposition] = (s.dispositions[x.disposition] ?? 0) + x.count;
  }
  return [...byDay.values()].map(({ orgs, bySource, ...d }) => ({
    ...d,
    reporters: [...orgs].sort(),
    sources: [...bySource.values()].sort((a, b) => b.messages - a.messages).slice(0, 50),
  }));
}
