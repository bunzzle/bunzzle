import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { rfc5322Date } from "../mime/encodings.ts";
import { b } from "../validate/schema.ts";
import {
  Aggregator,
  type AttemptEvent,
  parseTlsRpt,
  reportMail,
  type TlsReport,
} from "./report.ts";

const DAY = 86_400_000;
const LAST = "tlsrpt_last_day";

export interface TlsReportDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  delivery: RpcClient;
  org: string;
  contact: string;
  from: string | null;
  enqueue: (from: string, to: string, data: string) => Promise<string>;
  now?: () => number;
}

const posted = b.union([
  b.object({ ok: b.literal(true), status: b.number() }),
  b.object({ ok: b.literal(false), error: b.string() }),
]);

function attempts(db: Database, start: number, end: number): Aggregator {
  const agg = new Aggregator();
  const rows = db
    .query<{ data: string | null }, [number, number]>(
      "SELECT data FROM events WHERE kind = 'attempt' AND occurred_at >= ? AND occurred_at < ?",
    )
    .iterate(start, end);
  for (const row of rows) {
    if (!row.data) continue;
    const d = JSON.parse(row.data) as Partial<AttemptEvent>;
    if (typeof d.target !== "string" || !Array.isArray(d.sessions)) continue;
    agg.add({
      target: d.target,
      source: typeof d.source === "string" ? d.source : null,
      sts: d.sts ?? null,
      sessions: d.sessions,
    });
  }
  return agg;
}

export async function sendTlsReports(
  deps: TlsReportDeps,
): Promise<{ day: string; sent: number } | null> {
  const now = (deps.now ?? Date.now)();
  const start = Math.floor(now / DAY) * DAY - DAY;
  const last = deps.db
    .query<{ value: string }, [string]>("SELECT value FROM settings WHERE key = ?")
    .get(LAST)?.value;
  if (last !== undefined && Number(last) >= start) return null;
  const day = new Date(start).toISOString().slice(0, 10);
  const agg = attempts(deps.db, start, start + DAY);
  const domains = agg.domains();
  let sent = 0;
  for (let i = 0; i < domains.length; i += 20) {
    const batch = domains.slice(i, i + 20);
    const txt = await deps.delivery.call(
      "dns",
      { queries: batch.map((d) => ({ name: `_smtp._tls.${d}`, type: "TXT" as const })) },
      { result: b.record(b.string(), b.array(b.string())), timeoutMs: 60_000 },
    );
    for (const domain of batch) {
      const rua = parseTlsRpt(txt[`TXT:_smtp._tls.${domain}`] ?? []);
      if (!rua) continue;
      const report = agg.report(domain, {
        org: deps.org,
        contact: deps.contact,
        start,
        end: start + DAY - 1_000,
        id: `${day}.${domain}@${deps.org}`,
      });
      if (!report) continue;
      sent += await deliverReport(deps, domain, report, rua.https, rua.mailto);
    }
  }
  await deps.writer.run((d) =>
    d
      .query<unknown, [string, string, number]>(
        `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      )
      .run(LAST, String(start), now),
  );
  if (sent > 0) deps.log.info("TLS reports sent", { day, reports: sent });
  return { day, sent };
}

async function deliverReport(
  deps: TlsReportDeps,
  domain: string,
  report: TlsReport,
  https: string[],
  mailto: string[],
): Promise<number> {
  let sent = 0;
  for (const url of https) {
    const r = await deps.delivery
      .call(
        "postWebhook",
        {
          url,
          headers: { "Content-Type": "application/tlsrpt+json" },
          body: JSON.stringify(report),
        },
        { result: posted, timeoutMs: 60_000 },
      )
      .catch((err: Error) => ({ ok: false as const, error: err.message }));
    if (r.ok) sent++;
    else deps.log.warn("could not post a TLS report", { domain, url, error: r.error });
  }
  if (!deps.from) return sent;
  for (const to of mailto) {
    const from = deps.from;
    const data = reportMail(report, domain, {
      from,
      to,
      submitter: deps.org,
      messageId: `<${Bun.randomUUIDv7()}@${from.slice(from.lastIndexOf("@") + 1)}>`,
      date: rfc5322Date(new Date()),
    });
    try {
      await deps.enqueue(from, to, data);
      sent++;
    } catch (err) {
      deps.log.warn("could not queue a TLS report", { domain, to, error: (err as Error).message });
    }
  }
  return sent;
}
