import type { Database } from "bun:sqlite";
import { type Clock, systemClock } from "../core/clock.ts";
import { appendEvent } from "../core/events.ts";
import type { ClaimedJob } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import { type Apply, defer, fail, type Outcome, ok, unknown } from "../core/outcome.ts";
import { clampHint } from "../core/retry.ts";
import type { Destination } from "../dns/mx.ts";
import { type Classification, classify } from "../replies/classify.ts";
import { providerOf, siteOf } from "../routing/providers.ts";
import {
  type DeliveryOptions,
  type DeliveryReport,
  deliverTo,
  findDestination,
} from "../smtp/deliver.ts";
import type { RecipientResult } from "../smtp/session.ts";
import { getPath, type Path, pathDelivered, pauseDuration, pausePath, slowPath } from "./paths.ts";
import { type EmailPayload, pendingRecipients, type RecipientState } from "./queue.ts";

export interface DeliveryHandlerOptions extends DeliveryOptions {
  db: Database;
  log: Logger;
  clock?: Clock;
  source?: string;
  pauseMs?: number;
  maxPauseMs?: number;
  slowMs?: number;
  busyRetryMs?: number;
}

interface Update {
  address: string;
  status: RecipientState;
  attempted: boolean;
  result: RecipientResult | null;
  verdict: Classification | null;
  reply: string;
}

const SOURCE = "delivery";

function siteFor(destination: Destination, domain: string): string {
  if (destination.kind !== "targets") return domain;
  return providerOf(destination.mxHosts[0] ?? "")?.id ?? siteOf(destination.mxHosts);
}

function stateOf(r: RecipientResult, v: Classification): RecipientState {
  if (r.status === "delivered") return "delivered";
  if (r.status === "unknown") return "unknown";
  if (v.action === "fail-recipient" || v.action === "fail-message") return "bounced";
  return "deferred";
}

function sessionsOf(report: DeliveryReport) {
  return report.sessions.map((s) => ({
    host: s.host,
    address: s.address,
    phase: s.phase,
    error: s.error,
    tls: s.tls,
  }));
}

export function deliveryHandler(o: DeliveryHandlerOptions) {
  const clock = o.clock ?? systemClock;
  const source = o.source ?? o.localAddress ?? "default";
  const pauseMs = o.pauseMs ?? 3_600_000;
  const maxPauseMs = o.maxPauseMs ?? 12 * 3_600_000;
  const slowMs = o.slowMs ?? 10 * 60_000;
  const busyRetryMs = o.busyRetryMs ?? 60_000;
  const busy = new Map<string, number>();

  const record =
    (job: ClaimedJob, updates: Update[], effects: (db: Database, now: number) => void): Apply =>
    (db, settled, now) => {
      const event = (kind: string, data: Record<string, unknown>) =>
        appendEvent(db, { messageId: job.messageId, kind, source: SOURCE, at: now, data });
      const write = db.query<
        unknown,
        [
          RecipientState,
          number,
          number | null,
          string | null,
          string,
          string | null,
          string | null,
          number,
          number,
          string,
          string,
        ]
      >(
        `UPDATE recipients SET status = ?, attempts = attempts + ?, code = ?, enhanced = ?,
           reply = ?, class = ?, scope = ?, suppress = ?, updated_at = ?
         WHERE job_id = ? AND address = ?`,
      );
      for (const u of updates) {
        write.run(
          u.status,
          u.attempted ? 1 : 0,
          u.result?.code ?? null,
          u.result?.enhanced ?? null,
          u.reply,
          u.verdict?.class ?? null,
          u.verdict?.scope ?? null,
          u.verdict?.suppress ? 1 : 0,
          now,
          job.id,
          u.address,
        );
        if (!u.attempted) continue;
        event("recipient", {
          address: u.address,
          status: u.status,
          phase: u.result?.phase ?? null,
          code: u.result?.code ?? null,
          enhanced: u.result?.enhanced ?? null,
          reply: u.reply,
          class: u.verdict?.class ?? null,
          scope: u.verdict?.scope ?? null,
          action: u.verdict?.action ?? null,
          rule: u.verdict?.rule ?? null,
        });
        if (u.verdict?.suppress) {
          event("suppression_candidate", { address: u.address, class: u.verdict.class });
        }
      }
      effects(db, now);
      if (settled === "dead") {
        const expired = job.expiresAt !== null && now >= job.expiresAt;
        const why = expired ? "expired" : "retries-exhausted";
        db.query<unknown, [string, string, number, string]>(
          `UPDATE recipients SET status = 'failed', class = ?, reply = coalesce(reply, ?),
             updated_at = ?
           WHERE job_id = ? AND status IN ('queued', 'deferred', 'unknown')`,
        ).run(why, why, now, job.id);
      }
    };

  return async (job: ClaimedJob): Promise<Outcome> => {
    const { db, log } = o;
    const now = clock.now();
    const email = job.payload as EmailPayload;
    const pending = pendingRecipients(db, job.id);
    if (pending.length === 0) return ok.done;
    const none = () => {};

    if (job.expiresAt !== null && now >= job.expiresAt) {
      return {
        ...fail("expired", "the email expired before it could be delivered"),
        apply: record(job, [], none),
      };
    }

    const destination = await findDestination(job.target, o);
    const site = siteFor(destination, job.target);
    const path: Path = getPath(db, source, site, now);
    const waiting = (reason: string, delayMs: number): Outcome => ({
      ...defer(reason, delayMs),
      apply: record(
        job,
        pending.map((address) => ({
          address,
          status: "deferred",
          attempted: false,
          result: null,
          verdict: null,
          reply: reason,
        })),
        none,
      ),
    });

    if (path.state === "paused" && path.until !== null) {
      return waiting(`path ${source} → ${site} paused: ${path.reason}`, path.until - now);
    }
    if (path.state === "slowed" && (busy.get(site) ?? 0) > 0) {
      return waiting(`path ${source} → ${site} slowed: ${path.reason}`, busyRetryMs);
    }

    busy.set(site, (busy.get(site) ?? 0) + 1);
    let report: DeliveryReport;
    try {
      report = await deliverTo(
        destination,
        {
          domain: job.target,
          from: email.from,
          recipients: pending,
          data: email.data,
          smtpUtf8: email.smtpUtf8,
          requireTls: email.requireTls,
        },
        o,
      );
    } finally {
      const n = (busy.get(site) ?? 1) - 1;
      if (n > 0) busy.set(site, n);
      else busy.delete(site);
    }

    const provider = report.provider?.id ?? null;
    const atDot = report.recipients.filter((r) => r.phase === "dot").length;
    const updates: Update[] = report.recipients.map((r) => {
      const verdict = classify({
        phase: r.phase,
        code: r.code,
        enhanced: r.enhanced,
        text: r.reply,
        provider,
        shared: r.phase === "dot" && atDot > 1,
      });
      return {
        address: r.address,
        status: stateOf(r, verdict),
        attempted: true,
        result: r,
        verdict,
        reply: r.reply,
      };
    });

    const verdicts = updates.flatMap((u) => (u.verdict ? [u.verdict] : []));
    const pauseBy = updates.find((u) => u.verdict?.action === "pause-path");
    const slowBy = updates.find((u) => u.verdict?.action === "slow-path");
    const delivered = updates.some((u) => u.status === "delivered");
    let pausedUntil: number | null = null;
    if (pauseBy) pausedUntil = now + pauseDuration(path.pauses, pauseMs, maxPauseMs);

    const effects = (d: Database, at: number) => {
      const event = (kind: string, data: Record<string, unknown>) =>
        appendEvent(d, { messageId: job.messageId, kind, source: SOURCE, at, data });
      event("attempt", {
        target: job.target,
        provider,
        policy: report.policy,
        mx: report.destination.kind === "targets" ? report.destination.mxHosts : [],
        sessions: sessionsOf(report),
      });
      if (pauseBy && pausedUntil !== null) {
        pausePath(d, path, pausedUntil, pauseBy.reply, at);
        event("path_paused", { source, site, until: pausedUntil, reason: pauseBy.reply });
      } else if (slowBy) {
        slowPath(d, path, at + slowMs, slowBy.reply, at);
        event("path_slowed", { source, site, until: at + slowMs, reason: slowBy.reply });
      } else if (delivered) {
        pathDelivered(d, path, at);
      }
    };

    if (pauseBy) {
      log.error("path paused: our IP looks blocked at this site", {
        source,
        site,
        until: pausedUntil,
        reply: pauseBy.reply,
      });
    } else if (slowBy) {
      log.warn("path slowed", { source, site, reply: slowBy.reply });
    }
    for (const u of updates) {
      if (u.verdict?.alert && u.verdict.scope === "sender") {
        log.error("sender setup rejected by receiver", {
          domain: job.target,
          address: u.address,
          reply: u.reply,
        });
      }
    }

    const apply = record(job, updates, effects);
    const summary = (status: RecipientState) =>
      updates
        .filter((u) => u.status === status)
        .map((u) => `${u.address}: ${u.reply}`)
        .join("; ");

    if (updates.some((u) => u.status === "unknown")) {
      return { ...unknown(`no reply after the end of data: ${summary("unknown")}`), apply };
    }
    if (updates.some((u) => u.status === "deferred")) {
      let delay: number | undefined;
      if (pausedUntil !== null) delay = pausedUntil - now;
      else {
        const hints = verdicts.flatMap((v) => (v.hintMs !== null ? [v.hintMs] : []));
        if (hints.length > 0) delay = clampHint(Math.max(...hints));
      }
      return { ...defer(summary("deferred"), delay), apply };
    }
    if (delivered) return { ...ok.done, apply };
    return { ...fail("bounced", summary("bounced")), apply };
  };
}
