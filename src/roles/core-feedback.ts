import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { BodySealer, type EpochPublicKey } from "../crypto/envelope.ts";
import { dmarcSummary, saveDmarcReport } from "../dmarc/store.ts";
import { findDomain, getDomain } from "../domains/domains.ts";
import { type Applied, applyInbound, applyUnsubscribe, type Via } from "../inbound/apply.ts";
import { findRoute } from "../inbound/routes.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import {
  listSuppressions,
  removeSuppression,
  sharedSuppression,
  suppress,
} from "../suppressions/store.ts";
import { b } from "../validate/schema.ts";
import { projectEvents } from "../webhooks/project.ts";
import {
  claimFor,
  createWebhook,
  type Delivery,
  deleteWebhook,
  EVENT_TYPES,
  enabledWebhooks,
  getResend,
  listDeliveries,
  listWebhooks,
  type Pending,
  queueResend,
  type Resend,
  recordAttempt,
  resendDelivery,
  resendStep,
  resetSending,
  settleDelivery,
} from "../webhooks/store.ts";
import { resolveActor } from "./actor.ts";
import { DOMAIN, dmarcWire, project, reportWire, tokenHash } from "./wire.ts";

export interface FeedbackDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  currentKey: () => Promise<EpochPublicKey>;
  scale?: number;
  now?: () => number;
  sharedBounces?: () => boolean;
}

const tokenResult = b
  .object({ purpose: b.enum(["b", "u", "o", "c"]), messageId: b.string() })
  .nullable();

const WEBHOOK_SLOTS = 64;
const WEBHOOK_SLOTS_PER_ENDPOINT = 16;
const iso = (t: number) => new Date(t).toISOString();

const resendView = (r: Resend) => ({
  object: "webhook_resend",
  id: r.id,
  webhook_id: r.webhookId,
  from: iso(r.from),
  to: iso(r.to),
  failed: r.failed,
  state: r.state,
  resent: r.resent,
  created_at: iso(r.createdAt),
  updated_at: iso(r.updatedAt),
});

const deliveryView = (d: Delivery) => ({
  object: "webhook_delivery",
  id: d.id,
  type: d.type,
  state: d.state,
  created_at: iso(d.createdAt),
  next_attempt_at: d.nextAt === null ? null : iso(d.nextAt),
  attempts: d.attempts.map((a) => ({
    at: iso(a.at),
    status: a.status,
    error: a.error,
    duration_ms: a.durationMs,
  })),
});

export function feedbackMethods(deps: FeedbackDeps) {
  const { db, writer, log, signer, delivery } = deps;
  const sealer = new BodySealer();
  const now = deps.now ?? Date.now;

  const readToken = (token: string) =>
    signer.call("readToken", { token }, { result: tokenResult, timeoutMs: 10_000 });

  const route = async (address: string): Promise<{ via: Via; messageId: string | null } | null> => {
    const at = address.lastIndexOf("@");
    if (at <= 0) return null;
    const local = address.slice(0, at).toLowerCase();
    const domain = address.slice(at + 1).toLowerCase();
    if (local === "fbl" && domain.startsWith("bounce."))
      return { via: "feedback", messageId: null };
    const m = /^([bu])-([a-z2-7]{20,80})$/.exec(local);
    if (!m) return null;
    const t = await readToken(m[2] as string);
    if (!t || t.purpose !== m[1]) return null;
    return { via: m[1] === "b" ? "bounce" : "unsubscribe", messageId: t.messageId };
  };

  const dmarcDomain = (address: string): string | null => {
    const m = /^dmarc@bounce\.(.+)$/i.exec(address.trim());
    const domain = m?.[1]?.toLowerCase();
    return domain && DOMAIN.test(domain) && findDomain(db, domain) ? domain : null;
  };

  const methods: Methods = {
    inboundRecipient: method(b.object({ address: b.string().max(320) }), async ({ address }) => ({
      accept:
        findRoute(db, address) !== null ||
        dmarcDomain(address) !== null ||
        (await route(address)) !== null,
    })),

    inboundDmarc: method(
      b.object({ recipients: b.array(b.string().max(320)).min(1).max(10), report: dmarcWire }),
      async ({ recipients, report }) => {
        const domains = recipients.map(dmarcDomain).filter((d) => d !== null);
        if (!domains.includes(report.domain)) {
          throw new RpcError("invalid", "the report is not about the domain it was sent to");
        }
        const saved = await writer.run((d) => saveDmarcReport(d, report, now()));
        log.info("DMARC report received", {
          domain: report.domain,
          org: report.org,
          rows: report.rows.length,
          duplicate: !saved,
        });
        return { saved };
      },
    ),

    dmarcReports: method(
      b.object({
        tokenHash,
        project,
        domain: b.string().max(253),
        days: b.number().int().min(1).max(90),
      }),
      (p) => {
        const actor = resolveActor(db, p, "read");
        const name = p.domain.toLowerCase();
        if (!DOMAIN.test(name) || !getDomain(db, actor.project, name)) {
          throw new RpcError("not-found", "domain not found");
        }
        return { object: "list", domain: name, data: dmarcSummary(db, name, p.days, now()) };
      },
    ),

    inboundReport: method(
      b.object({
        recipients: b.array(b.string().max(320)).min(1).max(10),
        report: reportWire,
        raw: b.string().max(2 * 1024 * 1024),
      }),
      async ({ recipients, report, raw }) => {
        const routes = new Map<string, { via: Via; messageId: string | null }>();
        for (const address of recipients) {
          const r = await route(address);
          if (!r) continue;
          if (r.via === "feedback" || (r.via === "bounce" && !r.messageId)) {
            const t = report.ref ? await readToken(report.ref) : null;
            r.messageId = t && t.purpose === "b" ? t.messageId : null;
          }
          routes.set(`${r.via}|${r.messageId}`, r);
        }
        if (routes.size === 0) throw new RpcError("invalid", "no valid recipient");
        const sealedId = Bun.randomUUIDv7();
        const sealed = await sealer.seal(await deps.currentKey(), sealedId, raw);
        const results: Applied[] = [];
        let first = true;
        for (const r of routes.values()) {
          const id: string = first ? sealedId : Bun.randomUUIDv7();
          const raw = first ? sealed : null;
          first = false;
          const applied: Applied = await writer.run((d) =>
            applyInbound(d, { id, via: r.via, messageId: r.messageId, report, raw }, now()),
          );
          results.push(applied);
        }
        for (const r of results) {
          if (r.kind !== "unmatched")
            log.info("feedback received", { kind: r.kind, count: r.recipients.length });
        }
        return results;
      },
    ),

    unsubscribe: method(b.object({ token: b.string().max(100) }), async ({ token }) => {
      const t = await readToken(token);
      if (t?.purpose !== "u") throw new RpcError("not-found", "unknown unsubscribe link");
      const address = await writer.run((d) => applyUnsubscribe(d, t.messageId, "one-click", now()));
      if (!address) throw new RpcError("not-found", "unknown unsubscribe link");
      return { unsubscribed: true };
    }),

    listSuppressions: method(b.object({ tokenHash, project }), (p) => {
      const actor = resolveActor(db, p, "read");
      return listSuppressions(db, actor.project, now(), deps.sharedBounces?.() ?? false).map(
        (s) => ({
          object: "suppression",
          email: s.address,
          scope: s.scope,
          reason: s.reason,
          detail: s.detail,
          email_id: s.sourceMessageId,
          created_at: new Date(s.createdAt).toISOString(),
          expires_at: s.expiresAt === null ? null : new Date(s.expiresAt).toISOString(),
        }),
      );
    }),

    addSuppression: method(
      b.object({
        tokenHash,
        project,
        email: b.string().email().max(320),
        scope: b.enum(["all", "bulk"]).default("all"),
      }),
      async (p) => {
        const actor = resolveActor(db, p, "full");
        await writer.run((d) =>
          suppress(d, actor.project, { address: p.email, scope: p.scope, reason: "manual" }, now()),
        );
        return { email: p.email.toLowerCase(), scope: p.scope, reason: "manual" };
      },
    ),

    removeSuppression: method(
      b.object({
        tokenHash,
        project,
        email: b.string().max(320),
        scope: b.enum(["all", "bulk"]).nullable().default(null),
      }),
      async (p) => {
        const actor = resolveActor(db, p, "full");
        const n = await writer.run((d) => removeSuppression(d, actor.project, p.email, p.scope));
        if (
          n === 0 &&
          deps.sharedBounces?.() &&
          sharedSuppression(db, actor.project, p.email, now())
        ) {
          throw new RpcError(
            "invalid",
            "this address bounced as not existing; it is on the server's shared list, which only the operator can turn off",
          );
        }
        if (n === 0) throw new RpcError("not-found", "that address is not suppressed");
        return { email: p.email.toLowerCase(), removed: n };
      },
    ),

    createWebhook: method(
      b.object({
        tokenHash,
        project,
        url: b.string().url().max(2048),
        events: b.array(b.enum(EVENT_TYPES)).max(EVENT_TYPES.length).default([]),
      }),
      async (p) => {
        const actor = resolveActor(db, p, "full");
        const u = new URL(p.url);
        if (u.protocol !== "https:" && u.protocol !== "http:") {
          throw new RpcError("invalid", "webhook URLs must be http or https");
        }
        const hook = await writer.run((d) =>
          createWebhook(d, actor.project, p.url, p.events, now()),
        );
        const secret = await signer.call("webhookSecret", { id: hook.id }, { result: b.string() });
        return {
          object: "webhook",
          id: hook.id,
          endpoint: hook.url,
          events: hook.events,
          signing_secret: secret,
          created_at: new Date(hook.createdAt).toISOString(),
        };
      },
    ),

    listWebhooks: method(b.object({ tokenHash, project }), (p) => {
      const actor = resolveActor(db, p, "read");
      return listWebhooks(db, actor.project).map((h) => ({
        object: "webhook",
        id: h.id,
        endpoint: h.url,
        events: h.events,
        created_at: new Date(h.createdAt).toISOString(),
      }));
    }),

    listWebhookDeliveries: method(
      b.object({
        tokenHash,
        project,
        id: b.string().max(64),
        from: b.number().int().min(0).optional(),
        to: b.number().int().min(0).optional(),
        failed: b.boolean().default(false),
        before: b.string().max(64).optional(),
        limit: b.number().int().min(1).max(100).default(50),
      }),
      (p) => {
        const actor = resolveActor(db, p, "read");
        const list = listDeliveries(db, actor.project, p.id, p);
        if (!list) throw new RpcError("not-found", "webhook not found");
        return list.map(deliveryView);
      },
    ),

    resendWebhookDelivery: method(
      b.object({ tokenHash, project, id: b.string().max(64), delivery: b.string().max(64) }),
      async (p) => {
        const actor = resolveActor(db, p, "full");
        const r = await writer.run((d) =>
          resendDelivery(d, actor.project, p.id, p.delivery, now()),
        );
        if (r === "not-found") throw new RpcError("not-found", "webhook delivery not found");
        if (r === "in-flight") {
          throw new RpcError("invalid", "this delivery is still being sent or waiting to retry");
        }
        return { resent: 1 };
      },
    ),

    resendWebhookRange: method(
      b.object({
        tokenHash,
        project,
        id: b.string().max(64),
        from: b.number().int().min(0),
        to: b.number().int().min(0),
        failed: b.boolean().default(false),
      }),
      async (p) => {
        const actor = resolveActor(db, p, "full");
        if (p.to <= p.from) throw new RpcError("invalid", "`to` must be after `from`");
        const r = await writer.run((d) =>
          queueResend(d, actor.project, p.id, { from: p.from, to: p.to, failed: p.failed }, now()),
        );
        if (!r) throw new RpcError("not-found", "webhook not found");
        if ("busy" in r) {
          throw new RpcError("started", `resend ${r.busy} of this webhook is still running`);
        }
        return resendView(r);
      },
    ),

    getWebhookResend: method(
      b.object({ tokenHash, project, id: b.string().max(64), resend: b.string().max(64) }),
      (p) => {
        const actor = resolveActor(db, p, "read");
        const r = getResend(db, actor.project, p.id, p.resend);
        if (!r) throw new RpcError("not-found", "resend not found");
        return resendView(r);
      },
    ),

    deleteWebhook: method(b.object({ tokenHash, project, id: b.string().max(64) }), async (p) => {
      const actor = resolveActor(db, p, "full");
      if (!(await writer.run((d) => deleteWebhook(d, actor.project, p.id, now())))) {
        throw new RpcError("not-found", "webhook not found");
      }
      return { id: p.id, deleted: true };
    }),
  };

  const projectAll = () => writer.run((d) => projectEvents(d, now()));

  const busy = new Map<string, number>();
  let inFlight = 0;
  let turn = 0;
  let claiming = false;
  let again = false;

  const send = async (d: Pending) => {
    let ok = false;
    let error: string | null = null;
    let status: number | null = null;
    const started = now();
    try {
      const timestamp = Math.floor(now() / 1000);
      const msgId = `msg_${d.id}`;
      const signature = await signer.call(
        "signWebhook",
        { id: d.webhookId, msgId, timestamp, body: d.payload },
        { result: b.string(), timeoutMs: 10_000 },
      );
      const r = await delivery.call(
        "postWebhook",
        {
          url: d.url,
          body: d.payload,
          headers: {
            "webhook-id": msgId,
            "webhook-timestamp": String(timestamp),
            "webhook-signature": signature,
          },
        },
        {
          timeoutMs: 20_000,
          result: b.union([
            b.object({ ok: b.literal(true), status: b.number() }),
            b.object({ ok: b.literal(false), error: b.string() }),
          ]),
        },
      );
      if (r.ok) {
        status = r.status;
        ok = r.status >= 200 && r.status < 300;
        if (!ok) error = `endpoint answered ${r.status}`;
      } else error = r.error;
    } catch (err) {
      error = (err as Error).message;
    }
    const at = now();
    const result = await writer.run((w) => {
      recordAttempt(w, {
        deliveryId: d.id,
        at,
        status,
        error,
        durationMs: Math.max(0, at - started),
      });
      return settleDelivery(w, d, ok, error, at, deps.scale ?? 1);
    });
    if (result === "failed") {
      log.warn("webhook delivery gave up", { webhook: d.webhookId, type: d.type, error });
    }
  };

  const start = (d: Pending) => {
    inFlight++;
    busy.set(d.webhookId, (busy.get(d.webhookId) ?? 0) + 1);
    void send(d)
      .catch((err: Error) => log.error("webhook send failed", { error: err.message }))
      .finally(() => {
        inFlight--;
        const n = (busy.get(d.webhookId) ?? 1) - 1;
        if (n > 0) busy.set(d.webhookId, n);
        else busy.delete(d.webhookId);
        dispatch().catch((err: Error) =>
          log.error("webhook dispatch failed", { error: err.message }),
        );
      });
  };

  const dispatch = async () => {
    if (claiming) {
      again = true;
      return;
    }
    claiming = true;
    try {
      do {
        again = false;
        if (inFlight >= WEBHOOK_SLOTS) break;
        const due = await writer.run((w) => {
          const ids = enabledWebhooks(w);
          const out: Pending[] = [];
          const first = ids.length ? turn++ % ids.length : 0;
          for (let k = 0; k < ids.length; k++) {
            const room = WEBHOOK_SLOTS - inFlight - out.length;
            if (room <= 0) break;
            const id = ids[(first + k) % ids.length] as string;
            const free = Math.min(room, WEBHOOK_SLOTS_PER_ENDPOINT - (busy.get(id) ?? 0));
            if (free > 0) out.push(...claimFor(w, id, now(), free));
          }
          return out;
        });
        for (const d of due) start(d);
      } while (again);
    } finally {
      claiming = false;
    }
  };

  const recover = () => writer.run((d) => resetSending(d, now()));

  const resend = () => writer.run((d) => resendStep(d, now()));

  return { methods, project: projectAll, dispatch, recover, resend };
}
