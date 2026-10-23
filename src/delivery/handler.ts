import type { Database } from "bun:sqlite";
import type { PoolChoice } from "../accounts/pool-rules.ts";
import type { ProjectId } from "../accounts/projects.ts";
import { projectOfMessage } from "../accounts/projects.ts";
import type { SourceIp } from "../config.ts";
import { type Clock, systemClock } from "../core/clock.ts";
import { appendEvent } from "../core/events.ts";
import type { ClaimedJob } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import { type Apply, defer, fail, type Outcome, ok, requeue, unknown } from "../core/outcome.ts";
import { clampHint } from "../core/retry.ts";
import type { Destination } from "../dns/mx.ts";
import { countEmail } from "../emails/search.ts";
import { activeHold, countSender } from "../guards/guards.ts";
import { applyInbound } from "../inbound/apply.ts";
import { bucketOf, choose, countWarmup, type IpDown } from "../ips/warmup.ts";
import { domainOf } from "../mime/address.ts";
import { SUSPENDED_PREFIX, suspensionFor } from "../queue/control.ts";
import { type Classification, classify } from "../replies/classify.ts";
import { providerOfTargets, siteOf } from "../routing/providers.ts";
import type { JobContext } from "../scheduler/scheduler.ts";
import { type Admission, Shaper } from "../shaping/shaper.ts";
import type { DeliveryReport } from "../smtp/deliver.ts";
import type { RecipientResult } from "../smtp/session.ts";
import { suppress, suppressionForClass } from "../suppressions/store.ts";
import { bodyOf, type EmailPayload, pendingRecipients, type RecipientState } from "./queue.ts";
import {
  complains,
  SIMULATOR_DOMAIN,
  SIMULATOR_SOURCE,
  simulate,
  simulatorDestination,
} from "./simulator.ts";
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
  ips?: SourceIp[];
  holdRetryMs?: number;
  suspendRetryMs?: number;
  relayRoutes?: () => { targets: string[]; blocked: boolean } | null;
  listed?: (ip: string) => boolean;
  ipDown?: (ip: string) => IpDown | null;
  poolRules?: (job: {
    project: ProjectId;
    domain: string;
    provider: string | null;
    senderPool: string | null;
  }) => PoolChoice;
}

const RELAY = "relay";
const RENEW_AFTER_MS = 1_000;

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
  return providerOfTargets(destination.targets)?.id ?? siteOf(destination.mxHosts);
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
  const fixedSource = o.source ?? "default";
  const holdRetryMs = o.holdRetryMs ?? 15 * 60_000;
  const suspendRetryMs = o.suspendRetryMs ?? 5 * 60_000;
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
        const metric =
          u.status === "delivered"
            ? "delivered"
            : u.status === "bounced"
              ? "bounced"
              : u.status === "deferred"
                ? "deferred"
                : u.status === "failed"
                  ? "failed"
                  : null;
        if (metric) countEmail(db, job.messageId, metric, 1, now);
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
          const project = s ? projectOfMessage(db, job.messageId) : null;
          if (s && project) {
            suppress(
              db,
              project,
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
        const failed = db
          .query<unknown, [string, string, number, string]>(
            `UPDATE recipients SET status = 'failed', class = ?, reply = coalesce(reply, ?),
               updated_at = ?
             WHERE job_id = ? AND status IN ('queued', 'deferred', 'unknown')`,
          )
          .run(why, why, now, job.id).changes;
        countEmail(db, job.messageId, "failed", failed, now);
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

    const suspended = (provider: string | null): Outcome | null => {
      const s = suspensionFor(db, job.target, provider, now);
      if (!s) return null;
      let delay = s.until === null ? suspendRetryMs : Math.min(suspendRetryMs, s.until - now);
      if (job.expiresAt !== null) delay = Math.min(delay, job.expiresAt - now);
      return {
        ...requeue(`suspended by an operator: ${s.reason}`, Math.max(1_000, delay)),
        apply: (d, settled, at) => {
          if (settled !== "requeued") return;
          d.query<unknown, [string, number, string]>(
            `UPDATE recipients SET status = 'deferred', reply = ?, updated_at = ?
             WHERE job_id = ? AND status IN ('queued', 'deferred')`,
          ).run(`${SUSPENDED_PREFIX}: ${s.reason}`, at, job.id);
        },
      };
    };
    const byDomain = suspended(null);
    if (byDomain) return byDomain;

    const simulated = job.metadata["test"] === true || job.target === SIMULATOR_DOMAIN;
    let destination: Destination;
    try {
      destination = simulated
        ? simulatorDestination(job.target)
        : await o.transport.lookup(job.target);
    } catch (err) {
      return {
        ...defer(`delivery unavailable: ${(err as Error).message}`, busyRetryMs),
        apply: record(job, [], none),
      };
    }
    const target = targetFor(destination, job.target);
    const provider =
      destination.kind === "targets" ? (providerOfTargets(destination.targets)?.id ?? null) : null;
    const byProvider = provider ? suspended(provider) : null;
    if (byProvider) return byProvider;
    const lane = job.priority > 0 ? "bulk" : "transactional";
    const senderDomain = domainOf(email.from);
    const apiKeyId = (job.metadata["apiKeyId"] as string | null | undefined) ?? null;
    const waitFor = (
      reason: string,
      delayMs: number,
      visible: boolean,
      path: string | null,
    ): Outcome => ({
      ...requeue(reason, delayMs),
      ...(path ? { path } : {}),
      apply: (d, settled, at) => {
        if (!visible || settled !== "requeued") return;
        d.query<unknown, [string, number, string]>(
          `UPDATE recipients SET status = 'deferred', reply = ?, updated_at = ?
           WHERE job_id = ? AND status IN ('queued', 'deferred')`,
        ).run(`waiting: ${reason}`, at, job.id);
      },
    });

    if (lane === "bulk") {
      const hold =
        activeHold(db, `domain:${senderDomain}`, "bulk") ??
        activeHold(db, `project:${job.project}`, "bulk") ??
        (apiKeyId ? activeHold(db, `key:${apiKeyId}`, "bulk") : null);
      if (hold) return waitFor(`bulk mail on hold: ${hold.reason}`, holdRetryMs, true, null);
    }

    const routes =
      destination.kind === "targets" && !simulated ? (o.relayRoutes?.() ?? null) : null;
    const canFallback = routes?.blocked === true && !email.requireTls;
    const senderPool = (job.metadata["pool"] as string | null | undefined) ?? null;
    const rules =
      destination.kind === "targets" && !simulated && o.poolRules
        ? o.poolRules({
            project: job.project as ProjectId,
            domain: job.target,
            provider,
            senderPool,
          })
        : null;
    if (rules && rules.skipped.length > 0) {
      o.log.warn("pool rule skipped: its pool has no source IPs or belongs to another project", {
        rules: rules.skipped,
        project: job.project,
        domain: job.target,
      });
    }
    let via: typeof RELAY | null =
      routes &&
      (routes.targets.includes(job.target) ||
        (provider !== null && routes.targets.includes(provider)) ||
        (rules !== null && "relay" in rules))
        ? RELAY
        : null;
    let source: string = simulated ? SIMULATOR_SOURCE : RELAY;
    if (!via && !simulated) {
      const choice = o.ips?.length
        ? choose(
            db,
            o.ips,
            lane,
            target,
            provider,
            pending.length,
            now,
            (ip) => o.shaper.pausedUntil(Shaper.key(ip, target)),
            o.listed,
            rules && "pool" in rules ? rules.pool : senderPool,
            o.ipDown,
          )
        : { source: fixedSource };
      if ("wait" in choice) {
        if (!(choice.wait.blocked && canFallback)) {
          return waitFor(choice.wait.reason, choice.wait.delayMs, true, null);
        }
        via = RELAY;
      } else source = choice.source;
    }
    let pathKey = Shaper.key(source, target);

    let admission: Admission =
      destination.kind === "targets" && !simulated
        ? await o.shaper.admit(source, target, provider, lane, o.maxWaitMs)
        : { kind: "go", connections: 1, release: () => {} };
    if (admission.kind === "requeue" && admission.blocked && !via && canFallback) {
      via = RELAY;
      source = RELAY;
      pathKey = Shaper.key(source, target);
      admission = await o.shaper.admit(source, target, provider, lane, o.maxWaitMs);
    }
    if (admission.kind === "requeue") {
      const reason = admission.reason;
      return waitFor(
        reason,
        admission.delayMs,
        reason.includes("paused") || reason.includes("probing"),
        pathKey,
      );
    }
    const ticket = admission;
    admission = { kind: "go", connections: 1, release: () => {} };
    if (ctx && clock.now() - now >= RENEW_AFTER_MS && !(await ctx.renew())) {
      ticket.release("neutral", "");
      return requeue("lease lost while waiting", 0);
    }

    const attemptKey = `${job.id}#${job.attempt}`;
    const recallKey = job.unresolvedAttempt !== null ? `${job.id}#${job.unresolvedAttempt}` : null;
    let report: DeliveryReport;
    try {
      report = simulated
        ? simulate(job.target, pending, job.attempt)
        : await o.transport.deliver({
            key: attemptKey,
            recall: recallKey,
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
            source: via ? fixedSource : source,
            ...(via ? { via } : {}),
          });
    } catch (err) {
      ticket.release("neutral", "delivery role unreachable");
      const code = (err as { code?: unknown })?.code;
      if (code === "unavailable" || code === "invalid") {
        return {
          ...requeue(`delivery unavailable: ${(err as Error).message}`, busyRetryMs),
          path: pathKey,
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
      const reached = updates.filter(
        (u) => u.result && (u.result.phase === "rcpt" || u.result.phase === "dot"),
      );
      const hard = updates.filter((u) => u.status === "bounced" && u.verdict?.suppress).length;
      if (simulated) {
        for (const u of updates) {
          if (u.status !== "delivered" || !complains(u.address)) continue;
          applyInbound(
            d,
            {
              id: Bun.randomUUIDv7(),
              via: "feedback",
              messageId: job.messageId,
              report: { kind: "arf", ref: null, feedbackType: "abuse", originalRcpt: u.address },
              raw: null,
              simulated: true,
            },
            at,
          );
        }
      } else {
        countSender(
          d,
          senderDomain,
          lane,
          { delivered: updates.filter((u) => u.status === "delivered").length, hardBounced: hard },
          at,
        );
      }
      if (
        !via &&
        !simulated &&
        source !== "default" &&
        !o.ips?.find((x) => x.ip === source)?.established
      ) {
        countWarmup(
          d,
          source,
          bucketOf(provider),
          {
            sent: reached.length,
            delivered: reached.filter((u) => u.status === "delivered").length,
            deferred: reached.filter((u) => u.status === "deferred").length,
            bounced: hard,
            blocked: pauseBy ? 1 : 0,
          },
          at,
        );
      }
      if (report.recalled) {
        event("reconciled", { attempt: job.unresolvedAttempt, resent: false });
      }
      event("attempt", {
        target: job.target,
        lane,
        path: pathKey,
        source,
        ...(via ? { via } : {}),
        ...(simulated ? { simulated: true } : {}),
        sts: report.mtaSts ?? null,
        recalled: report.recalled ?? false,
        provider,
        policy: report.policy,
        mx: report.destination.kind === "targets" ? report.destination.mxHosts : [],
        sessions: sessionsOf(report),
      });
      const save = d.query<unknown, [string, number, number, string]>(
        "INSERT OR REPLACE INTO conversations (message_id, attempt_at, session, data) VALUES (?, ?, ?, ?)",
      );
      report.sessions.forEach((s, i) => {
        if (s.transcript?.length) save.run(job.messageId, at, i, JSON.stringify(s.transcript));
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
    const committed = () =>
      o.transport.forget?.(recallKey ? [attemptKey, recallKey] : [attemptKey]);
    const summary = (status: RecipientState) =>
      updates
        .filter((u) => u.status === status)
        .map((u) => `${u.address}: ${u.reply}`)
        .join("; ");

    if (updates.some((u) => u.status === "unknown")) {
      return {
        ...unknown(`no reply after the end of data: ${summary("unknown")}`),
        apply,
        committed,
        path: pathKey,
      };
    }
    if (updates.some((u) => u.status === "deferred")) {
      let delay: number | undefined;
      if (pausedUntil !== null) delay = pausedUntil - now;
      else {
        const hints = verdicts.flatMap((v) => (v.hintMs !== null ? [v.hintMs] : []));
        if (hints.length > 0) delay = clampHint(Math.max(...hints));
      }
      return { ...defer(summary("deferred"), delay), apply, committed, path: pathKey };
    }
    if (delivered) return { ...ok.done, apply, committed, path: pathKey };
    return { ...fail("bounced", summary("bounced")), apply, committed, path: pathKey };
  };
}
