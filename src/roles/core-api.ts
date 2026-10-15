import type { Database } from "bun:sqlite";
import { z } from "zod";
import {
  type ApiKey,
  allows,
  createKey,
  keyForHash,
  listKeys,
  revokeKey,
  type Scope,
  touchKey,
} from "../accounts/api-keys.ts";
import { countByState } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, sealBody } from "../crypto/envelope.ts";
import { emailExists, enqueueEmail, recipientsOf } from "../delivery/queue.ts";
import {
  type Domain,
  evaluate,
  expectedRecords,
  getDomain,
  listDomains,
  saveDomain,
} from "../domains/domains.ts";
import { findIdempotent, rememberIdempotent } from "../emails/idempotency.ts";
import { emailView } from "../emails/view.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { AddressError, asciiDomain, domainOf, normalizeAddress } from "../mime/address.ts";
import { senderDomainOf } from "../mime/from.ts";
import type { PathView } from "../shaping/shaper.ts";
import { suppressionFor } from "../suppressions/store.ts";
import { DOMAIN, enqueueParams, MESSAGE_ID, tokenHash } from "./wire.ts";

const MAX_SCHEDULE_MS = 72 * 3_600_000;

export interface CoreDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  currentKey: () => Promise<EpochPublicKey>;
  sourceIp: string | null;
  inboundHost?: string | null;
  paths?: () => PathView[];
  now?: () => number;
}

const OPERATOR: ApiKey = {
  id: "operator",
  name: "operator",
  prefix: "",
  scope: "full",
  domains: null,
  rateLimit: 0,
  createdAt: 0,
  lastUsedAt: null,
  revokedAt: null,
};

const publicKeyInfo = z.array(
  z.object({
    selector: z.string(),
    algorithm: z.enum(["rsa-sha256", "ed25519-sha256"]),
    publicKey: z.string(),
  }),
);

function domainView(d: Domain) {
  return {
    object: "domain",
    name: d.name,
    status: d.status,
    created_at: new Date(d.createdAt).toISOString(),
    checked_at: d.checkedAt === null ? null : new Date(d.checkedAt).toISOString(),
    records: d.records,
  };
}

function selectorBase(now: number): string {
  const d = new Date(now);
  return `bz${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

export function coreMethods(deps: CoreDeps): { methods: Methods; verifyPending(): Promise<void> } {
  const { db, writer, log, signer, delivery } = deps;
  const now = deps.now ?? Date.now;

  const caller = (hash: string | undefined, needed: Scope): ApiKey => {
    if (hash === undefined) return OPERATOR;
    const key = keyForHash(db, hash);
    if (!key) throw new RpcError("unauthenticated", "API key is invalid");
    if (!allows(key.scope, needed)) {
      throw new RpcError(
        "forbidden",
        `this API key cannot ${needed === "send" ? "send email" : needed === "read" ? "read" : "do this"}`,
      );
    }
    void writer.run((d) => touchKey(d, key.id, now()), { quiet: true }).catch(() => {});
    return key;
  };

  const domainName = (raw: string): string => {
    let name: string;
    try {
      name = asciiDomain(raw);
    } catch (err) {
      throw new RpcError("invalid", (err as Error).message);
    }
    if (!DOMAIN.test(name)) throw new RpcError("invalid", `invalid domain: ${raw}`);
    return name;
  };

  const verify = async (name: string): Promise<Domain> => {
    const d = getDomain(db, name);
    if (!d) throw new RpcError("not-found", `domain ${name} is not registered`);
    const queries = [
      ...new Map(
        d.records.map((r) => [`${r.type}:${r.name}`, { name: r.name, type: r.type }]),
      ).values(),
    ];
    const found = await delivery.call(
      "dns",
      { queries },
      {
        result: z.record(z.string(), z.array(z.string())),
        timeoutMs: 30_000,
      },
    );
    const checked = evaluate(d.records, found, deps.sourceIp);
    const next: Domain = { ...d, ...checked, checkedAt: now() };
    await writer.run((w) => saveDomain(w, next, now()));
    if (next.status !== d.status)
      log.info("domain status changed", { domain: name, status: next.status });
    return next;
  };

  const verifyPending = async () => {
    for (const d of listDomains(db).filter((x) => x.status === "pending")) {
      try {
        await verify(d.name);
      } catch (err) {
        log.warn("could not check domain", { domain: d.name, error: (err as Error).message });
      }
    }
  };

  const methods: Methods = {
    authenticate: method(z.object({ tokenHash: z.string() }), ({ tokenHash: hash }) => {
      const key = keyForHash(db, hash);
      if (!key) throw new RpcError("unauthenticated", "API key is invalid");
      return { id: key.id, scope: key.scope, domains: key.domains, rateLimit: key.rateLimit };
    }),

    enqueue: method(enqueueParams, async (p) => {
      const key = caller(p.tokenHash, "send");
      const id = p.id ?? Bun.randomUUIDv7();
      if (emailExists(db, id)) return { id, existed: true };
      let headerDomain: string;
      let envelopeFrom: string;
      try {
        headerDomain = senderDomainOf(p.data);
        envelopeFrom = normalizeAddress(p.from);
      } catch (err) {
        throw new RpcError("invalid", (err as Error).message);
      }
      if (domainOf(envelopeFrom) !== headerDomain) {
        throw new RpcError("invalid", "the envelope sender must use the From header's domain");
      }
      if (key.domains && !key.domains.includes(headerDomain)) {
        throw new RpcError("forbidden", `this API key cannot send from ${headerDomain}`);
      }
      const domain = getDomain(db, headerDomain);
      if (domain?.status !== "verified") {
        throw new RpcError(
          "unverified-domain",
          domain
            ? `The ${headerDomain} domain is not verified yet. Publish its DNS records, then verify it.`
            : `The ${headerDomain} domain is not registered. Add it with \`bunzzle domains add ${headerDomain}\`.`,
        );
      }
      const signerDomains = await signer.call("domains", {}, { result: z.array(z.string()) });
      if (!signerDomains.includes(headerDomain)) {
        throw new RpcError("unverified-domain", `no DKIM key for ${headerDomain}; it cannot send`);
      }
      const t = now();
      if (p.scheduledAt !== undefined && p.scheduledAt > t + MAX_SCHEDULE_MS) {
        throw new RpcError("invalid", "scheduled_at can be at most 72 hours ahead");
      }
      if (p.expiresAt !== undefined && p.expiresAt <= t) {
        throw new RpcError("invalid", "expires_at is in the past");
      }
      const idem =
        p.idempotencyKey !== undefined ? { key: p.idempotencyKey, hash: p.bodyHash ?? "" } : null;
      if (idem) {
        const prev = findIdempotent(db, key.id, idem.key, t);
        if (prev) {
          if (prev.bodyHash !== idem.hash) {
            throw new RpcError(
              "idempotency-conflict",
              "this Idempotency-Key was used with a different request",
            );
          }
          return { id: prev.messageId, existed: true };
        }
      }
      const lane = (p.priority ?? 0) > 0 ? "bulk" : "transactional";
      if (lane === "bulk" && p.recipients.length !== 1) {
        throw new RpcError("invalid", "a bulk email must have exactly one recipient");
      }
      const suppressed = new Map<string, { reason: string; scope: string }>();
      for (const raw of p.recipients) {
        let address: string;
        try {
          address = normalizeAddress(raw);
        } catch (err) {
          throw new RpcError("invalid", (err as Error).message);
        }
        const s = suppressionFor(db, address, lane, t);
        if (s) suppressed.set(address, { reason: s.reason, scope: s.scope });
      }
      const body = await sealBody(await deps.currentKey(), id, p.data);
      try {
        return await writer.run((d) => {
          if (idem) {
            const prev = findIdempotent(d, key.id, idem.key, t);
            if (prev) {
              if (prev.bodyHash !== idem.hash) {
                throw new RpcError(
                  "idempotency-conflict",
                  "this Idempotency-Key was used with a different request",
                );
              }
              return { id: prev.messageId, existed: true };
            }
          }
          enqueueEmail(
            d,
            {
              id,
              body,
              from: envelopeFrom,
              recipients: p.recipients,
              smtpUtf8: p.smtpUtf8,
              requireTls: p.requireTls,
              suppressed,
              metadata: {
                ...(p.meta ?? {}),
                apiKeyId: key.id === "operator" ? null : key.id,
                scheduledAt: p.scheduledAt ?? null,
              },
              ...(p.expiresAt !== undefined ? { expiresAt: p.expiresAt } : {}),
              ...(p.scheduledAt !== undefined ? { runAfter: p.scheduledAt } : {}),
              ...(p.priority !== undefined ? { priority: p.priority } : {}),
            },
            t,
          );
          if (idem) rememberIdempotent(d, key.id, idem.key, idem.hash, id, t);
          return { id, existed: false };
        });
      } catch (err) {
        if (err instanceof RpcError) throw err;
        if (emailExists(db, id)) return { id, existed: true };
        if (err instanceof AddressError) throw new RpcError("invalid", err.message);
        throw new RpcError("invalid", (err as Error).message);
      }
    }),

    getEmail: method(z.object({ tokenHash, id: z.string() }), ({ tokenHash: hash, id }) => {
      caller(hash, "read");
      if (!MESSAGE_ID.test(id)) throw new RpcError("not-found", "email not found");
      const view = emailView(db, id, now());
      if (!view) throw new RpcError("not-found", "email not found");
      return view;
    }),

    status: method(z.object({ id: z.string().regex(MESSAGE_ID) }), ({ id }) =>
      recipientsOf(db, id).map((r) => ({
        address: r.address,
        status: r.status,
        attempts: r.attempts,
        reply: r.reply,
        class: r.class,
      })),
    ),

    addDomain: method(z.object({ tokenHash, name: z.string().max(253) }), async (p) => {
      caller(p.tokenHash, "full");
      const name = domainName(p.name);
      const existing = getDomain(db, name);
      if (existing) return domainView(existing);
      const keys = await signer.call(
        "ensureKeys",
        { domain: name, selectorBase: selectorBase(now()) },
        { result: publicKeyInfo, timeoutMs: 60_000 },
      );
      const t = now();
      const d: Domain = {
        name,
        status: "pending",
        records: expectedRecords(name, keys, deps.sourceIp, deps.inboundHost ?? null),
        createdAt: t,
        checkedAt: null,
      };
      await writer.run((w) => {
        if (!getDomain(w, name)) saveDomain(w, d, t);
      });
      log.info("domain added", { domain: name });
      return domainView(getDomain(db, name) as Domain);
    }),

    getDomain: method(z.object({ tokenHash, name: z.string().max(253) }), (p) => {
      caller(p.tokenHash, "read");
      const d = getDomain(db, domainName(p.name));
      if (!d) throw new RpcError("not-found", "domain not found");
      return domainView(d);
    }),

    listDomains: method(z.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      return listDomains(db).map(domainView);
    }),

    verifyDomain: method(z.object({ tokenHash, name: z.string().max(253) }), async (p) => {
      caller(p.tokenHash, "full");
      return domainView(await verify(domainName(p.name)));
    }),

    createKey: method(
      z.object({
        name: z.string().min(1).max(100),
        scope: z.enum(["send", "read", "full"]),
        domains: z.array(z.string().max(253)).max(100).optional(),
        rateLimit: z.number().int().min(1).max(10_000).optional(),
      }),
      async (p) => {
        const domains = p.domains?.map(domainName);
        const { key, token } = await writer.run((d) =>
          createKey(
            d,
            {
              name: p.name,
              scope: p.scope,
              ...(domains ? { domains } : {}),
              ...(p.rateLimit ? { rateLimit: p.rateLimit } : {}),
            },
            now(),
          ),
        );
        return { ...key, token };
      },
    ),

    listKeys: method(z.object({}), () => listKeys(db)),

    revokeKey: method(z.object({ id: z.string().min(1).max(64) }), async ({ id }) => {
      if (!(await writer.run((d) => revokeKey(d, id, now())))) {
        throw new RpcError("not-found", "no active key with that id");
      }
      return { id, revoked: true };
    }),

    health: method(z.object({}), () => ({ ok: true, jobs: countByState(db) })),

    paths: method(z.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      return (deps.paths?.() ?? []).map((v) => ({
        object: "path",
        path: v.key,
        source: v.source,
        destination: v.target,
        provider: v.provider,
        state: v.mode,
        until: v.until === null ? null : new Date(v.until).toISOString(),
        rate_per_sec: v.rate,
        connections: v.connections,
        ceiling: { rate_per_sec: v.ceiling.ratePerSec, connections: v.ceiling.connections },
        in_flight: v.inflight,
        waiting: v.waiting,
        delivered: v.sent,
        changes: v.changes.map((c) => ({
          at: new Date(c.at).toISOString(),
          change: c.what,
          reason: c.reason,
          rate_per_sec: c.rate,
          connections: c.connections,
        })),
      }));
    }),
  };
  return { methods, verifyPending };
}
