import type { Database } from "bun:sqlite";
import { z } from "zod";
import { allows, keyForHash, type Scope } from "../accounts/api-keys.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, sealBody } from "../crypto/envelope.ts";
import { type Applied, applyInbound, applyUnsubscribe, type Via } from "../inbound/apply.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { listSuppressions, removeSuppression, suppress } from "../suppressions/store.ts";
import { projectEvents } from "../webhooks/project.ts";
import {
  claimDeliveries,
  createWebhook,
  deleteWebhook,
  EVENT_TYPES,
  listWebhooks,
  resetSending,
  settleDelivery,
} from "../webhooks/store.ts";
import { reportWire, tokenHash } from "./wire.ts";

export interface FeedbackDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  currentKey: () => Promise<EpochPublicKey>;
  scale?: number;
  now?: () => number;
}

const tokenResult = z.object({ purpose: z.enum(["b", "u"]), messageId: z.string() }).nullable();

export function feedbackMethods(deps: FeedbackDeps) {
  const { db, writer, log, signer, delivery } = deps;
  const now = deps.now ?? Date.now;

  const caller = (hash: string | undefined, needed: Scope) => {
    if (hash === undefined) return;
    const key = keyForHash(db, hash);
    if (!key) throw new RpcError("unauthenticated", "API key is invalid");
    if (!allows(key.scope, needed)) throw new RpcError("forbidden", "this API key cannot do this");
  };

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

  const methods: Methods = {
    inboundRecipient: method(z.object({ address: z.string().max(320) }), async ({ address }) => ({
      accept: (await route(address)) !== null,
    })),

    inboundReport: method(
      z.object({
        recipients: z.array(z.string().max(320)).min(1).max(10),
        report: reportWire,
        raw: z.string().max(2 * 1024 * 1024),
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
        const sealed = await sealBody(await deps.currentKey(), sealedId, raw);
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

    unsubscribe: method(z.object({ token: z.string().max(100) }), async ({ token }) => {
      const t = await readToken(token);
      if (t?.purpose !== "u") throw new RpcError("not-found", "unknown unsubscribe link");
      const address = await writer.run((d) => applyUnsubscribe(d, t.messageId, "one-click", now()));
      if (!address) throw new RpcError("not-found", "unknown unsubscribe link");
      return { unsubscribed: true };
    }),

    listSuppressions: method(z.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      return listSuppressions(db, now()).map((s) => ({
        object: "suppression",
        email: s.address,
        scope: s.scope,
        reason: s.reason,
        detail: s.detail,
        email_id: s.sourceMessageId,
        created_at: new Date(s.createdAt).toISOString(),
        expires_at: s.expiresAt === null ? null : new Date(s.expiresAt).toISOString(),
      }));
    }),

    addSuppression: method(
      z.object({
        tokenHash,
        email: z.string().email().max(320),
        scope: z.enum(["all", "bulk"]).default("all"),
      }),
      async (p) => {
        caller(p.tokenHash, "full");
        await writer.run((d) =>
          suppress(d, { address: p.email, scope: p.scope, reason: "manual" }, now()),
        );
        return { email: p.email.toLowerCase(), scope: p.scope, reason: "manual" };
      },
    ),

    removeSuppression: method(
      z.object({
        tokenHash,
        email: z.string().max(320),
        scope: z.enum(["all", "bulk"]).nullable().default(null),
      }),
      async (p) => {
        caller(p.tokenHash, "full");
        const n = await writer.run((d) => removeSuppression(d, p.email, p.scope));
        if (n === 0) throw new RpcError("not-found", "that address is not suppressed");
        return { email: p.email.toLowerCase(), removed: n };
      },
    ),

    createWebhook: method(
      z.object({
        tokenHash,
        url: z.string().url().max(2048),
        events: z.array(z.enum(EVENT_TYPES)).max(EVENT_TYPES.length).default([]),
      }),
      async (p) => {
        caller(p.tokenHash, "full");
        const u = new URL(p.url);
        if (u.protocol !== "https:" && u.protocol !== "http:") {
          throw new RpcError("invalid", "webhook URLs must be http or https");
        }
        const hook = await writer.run((d) => createWebhook(d, p.url, p.events, now()));
        const secret = await signer.call("webhookSecret", { id: hook.id }, { result: z.string() });
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

    listWebhooks: method(z.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      return listWebhooks(db).map((h) => ({
        object: "webhook",
        id: h.id,
        endpoint: h.url,
        events: h.events,
        created_at: new Date(h.createdAt).toISOString(),
      }));
    }),

    deleteWebhook: method(z.object({ tokenHash, id: z.string().max(64) }), async (p) => {
      caller(p.tokenHash, "full");
      if (!(await writer.run((d) => deleteWebhook(d, p.id, now())))) {
        throw new RpcError("not-found", "webhook not found");
      }
      return { id: p.id, deleted: true };
    }),
  };

  const project = () => writer.run((d) => projectEvents(d, now()));

  let sending = false;
  const dispatch = async () => {
    if (sending) return;
    sending = true;
    try {
      const due = await writer.run((d) => claimDeliveries(d, now(), 20));
      await Promise.all(
        due.map(async (d) => {
          let ok = false;
          let error: string | null = null;
          try {
            const timestamp = Math.floor(now() / 1000);
            const msgId = `msg_${d.id}`;
            const signature = await signer.call(
              "signWebhook",
              { id: d.webhookId, msgId, timestamp, body: d.payload },
              { result: z.string(), timeoutMs: 10_000 },
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
                result: z.union([
                  z.object({ ok: z.literal(true), status: z.number() }),
                  z.object({ ok: z.literal(false), error: z.string() }),
                ]),
              },
            );
            if (r.ok) {
              ok = r.status >= 200 && r.status < 300;
              if (!ok) error = `endpoint answered ${r.status}`;
            } else error = r.error;
          } catch (err) {
            error = (err as Error).message;
          }
          const result = await writer.run((w) =>
            settleDelivery(w, d, ok, error, now(), deps.scale ?? 1),
          );
          if (result === "failed") {
            log.warn("webhook delivery gave up", { webhook: d.webhookId, type: d.type, error });
          }
        }),
      );
    } finally {
      sending = false;
    }
  };

  const recover = () => writer.run((d) => resetSending(d, now()));

  return { methods, project, dispatch, recover };
}
