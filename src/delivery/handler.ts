import type { Database } from "bun:sqlite";
import { type Clock, systemClock } from "../core/clock.ts";
import { appendEvent } from "../core/events.ts";
import type { ClaimedJob } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import { type Apply, defer, fail, type Outcome, ok, requeue, unknown } from "../core/outcome.ts";
import { clampHint } from "../core/retry.ts";
import type { Destination } from "../dns/mx.ts";
import { domainOf } from "../mime/address.ts";
import { type Classification, classify } from "../replies/classify.ts";
import { providerOf, siteOf } from "../routing/providers.ts";
import type { JobContext } from "../scheduler/scheduler.ts";
import { type Admission, Shaper } from "../shaping/shaper.ts";
import type { DeliveryReport } from "../smtp/deliver.ts";
import type { RecipientResult } from "../smtp/session.ts";
import { suppress, suppressionForClass } from "../suppressions/store.ts";
import { bodyOf, type EmailPayload, pendingRecipients, type RecipientState } from "./queue.ts";
import type { DeliveryTransport } from "./transport.ts";

export interface DeliveryHandlerOptions {
  db: Database;
  log: Logger;
  transport: DeliveryTransport;
  clock?: Clock;
  source?: string;
  shaper: Shaper;
  busyRetryMs?: number;
  maxWaitMs?: number;
  bounceDomainFor?: (senderDomain: string) => string | null;
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

function targetFor(destination: Destination, domain: string): string {
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
    reused: s.reused ?? false,
    host: s.host,
    address: s.address,
    phase: s.phase,
    error: s.error,
    tls: s.tls,
  }));
}

export function deliveryHandler(o: DeliveryHandlerOptions) {
  const clock = o.clock ?? systemClock;
  const source = o.source ?? "default";
  const busyRetryMs = o.busyRetryMs ?? 60_000;

  const record =
    (
      job: ClaimedJob,
      updates: Update[],
      effects: (db: Database, now: number) => void,
      deadClass?: string,
    ): Apply =>
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
          const s = suppressionForClass(u.verdict.class);
          if (s) {
            suppress(
              db,
              {
                address: u.address,
                scope: s.scope,
                reason: s.reason,
                detail: u.reply,
                messageId: job.messageId,
                ttlMs: s.ttlMs,
              },
              now,
            );
            event("address_suppressed", {
              address: u.address,
              reason: s.reason,
              scope: s.scope,
              class: u.verdict.class,
            });
          }
        }
      }
      effects(db, now);
      if (settled === "dead") {
        const expired = job.expiresAt !== null && now >= job.expiresAt;
        const why = deadClass ?? (expired ? "expired" : "retries-exhausted");
        db.query<unknown, [string, string, number, string]>(
          `UPDATE recipients SET status = 'failed', class = ?, reply = coalesce(reply, ?),
             updated_at = ?
           WHERE job_id = ? AND status IN ('queued', 'deferred', 'unknown')`,
        ).run(why, why, now, job.id);
      }
    };

  return async (job: ClaimedJob, _signal?: AbortSignal, ctx?: JobContext): Promise<Outcome> => {
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

    const body = bodyOf(db, job.messageId);
    if (!body) {
      return {
        ...fail("body-gone", "the email body no longer exists"),
        apply: record(job, [], none, "body-gone"),
      };
    }

    let destination: Destination;
    try {
      destination = await o.transport.lookup(job.target);
    } catch (err) {
      return {
        ...defer(`delivery unavailable: ${(err as Error).message}`, busyRetryMs),
        apply: record(job, [], none),
      };
    }
    const target = targetFor(destination, job.target);
    const provider =
      destination.kind === "targets"
        ? (providerOf(destination.mxHosts[0] ?? "")?.id ?? null)
        : null;
    const pathKey = Shaper.key(source, target);
    const lane = job.priority > 0 ? "bulk" : "transactional";
    const setPath = (d: Database) =>
      d
        .query<unknown, [string, string]>("UPDATE jobs SET path = ? WHERE id = ?")
        .run(pathKey, job.id);

    let admission: Admission =
      destination.kind === "targets"
        ? await o.shaper.admit(source, target, provider, lane, o.maxWaitMs)
        : { kind: "go", connections: 1, release: () => {} };
    if (admission.kind === "requeue") {
      const reason = admission.reason;
      const visible = reason.includes("paused") || reason.includes("probing");
      return {
        ...requeue(reason, admission.delayMs),
        apply: (d, settled, at) => {
          setPath(d);
          if (!visible || settled !== "requeued") return;
          d.query<unknown, [string, number, string]>(
            `UPDATE recipients SET status = 'deferred', reply = ?, updated_at = ?
             WHERE job_id = ? AND status IN ('queued', 'deferred')`,
          ).run(`waiting: ${reason}`, at, job.id);
        },
      };
    }
    const ticket = admission;
    admission = { kind: "go", connections: 1, release: () => {} };
    if (ctx && !(await ctx.renew())) {
      ticket.release("neutral", "");
      return requeue("lease lost while waiting", 0);
    }

    let report: DeliveryReport;
    try {
      report = await o.transport.deliver({
        key: `${job.id}#${job.attempt}`,
        recall: job.unresolvedAttempt !== null ? `${job.id}#${job.unresolvedAttempt}` : null,
        messageId: job.messageId,
        domain: job.target,
        destination,
        from: email.from,
        recipients: pending,
        smtpUtf8: email.smtpUtf8,
        requireTls: email.requireTls,
        body,
        ...(destination.kind === "targets" ? { connections: ticket.connections } : {}),
        lane,
        bounceDomain: o.bounceDomainFor?.(domainOf(email.from)) ?? null,
      });
    } catch (err) {
      ticket.release("neutral", "delivery role unreachable");
      const code = (err as { code?: unknown })?.code;
      if (code === "unavailable" || code === "invalid") {
        return {
          ...requeue(`delivery unavailable: ${(err as Error).message}`, busyRetryMs),
          apply: (d) => setPath(d),
        };
      }
      throw err;
    }

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
    if (pauseBy) ticket.release("reputation", pauseBy.reply);
    else if (slowBy) ticket.release("rate", slowBy.reply);
    else if (delivered) ticket.release("success", "");
    else ticket.release("neutral", "");
    const pausedUntil = pauseBy ? o.shaper.pausedUntil(pathKey) : null;

    const effects = (d: Database, at: number) => {
      const event = (kind: string, data: Record<string, unknown>) =>
        appendEvent(d, { messageId: job.messageId, kind, source: SOURCE, at, data });
      setPath(d);
      if (report.recalled) {
        event("reconciled", { attempt: job.unresolvedAttempt, resent: false });
      }
      event("attempt", {
        target: job.target,
        lane,
        path: pathKey,
        recalled: report.recalled ?? false,
        provider,
        policy: report.policy,
        mx: report.destination.kind === "targets" ? report.destination.mxHosts : [],
        sessions: sessionsOf(report),
      });
      if (pauseBy) {
        event("path_paused", { path: pathKey, until: pausedUntil, reason: pauseBy.reply });
      } else if (slowBy) {
        event("path_slowed", { path: pathKey, reason: slowBy.reply });
      }
    };

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
