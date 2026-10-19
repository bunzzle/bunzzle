import type { Database } from "bun:sqlite";
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
import type { SourceIp } from "../config.ts";
import { countByState } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, sealBody } from "../crypto/envelope.ts";
import {
  cancelEmail,
  emailExists,
  enqueueEmail,
  recipientsOf,
  rescheduleEmail,
  scheduledEmail,
} from "../delivery/queue.ts";
import {
  type Domain,
  type DomainRecord,
  evaluate,
  expectedRecords,
  getDomain,
  listDomains,
  saveDomain,
} from "../domains/domains.ts";
import { findIdempotent, rememberIdempotent } from "../emails/idempotency.ts";
import { emailView } from "../emails/view.ts";
import {
  activeHold,
  anomalyThreshold,
  countKeyBulk,
  createHold,
  listHolds,
  releaseHold,
  senderRates,
} from "../guards/guards.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { dayOf, estimatedDays, listWarmup } from "../ips/warmup.ts";
import { collect, render } from "../metrics/metrics.ts";
import { AddressError, asciiDomain, domainOf, normalizeAddress } from "../mime/address.ts";
import { senderDomainOf } from "../mime/from.ts";
import { queueSummary, removeQueued, resume, type Suspension, suspend } from "../queue/control.ts";
import type { PathView } from "../shaping/shaper.ts";
import { suppressionFor } from "../suppressions/store.ts";
import { b } from "../validate/schema.ts";
import { DOMAIN, enqueueParams, MESSAGE_ID, tokenHash } from "./wire.ts";

const SUSPEND_TARGET =
  /^(domain:(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}|provider:[a-z0-9-]{1,40})$/;

const suspensionView = (s: Suspension) => ({
  target: s.target,
  reason: s.reason,
  until: s.until === null ? null : new Date(s.until).toISOString(),
  since: new Date(s.createdAt).toISOString(),
});

type EnqueueInput = Omit<b.output<typeof enqueueParams>, "tokenHash">;

const MAX_SCHEDULE_MS = 72 * 3_600_000;

export interface CoreDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  signer: RpcClient;
  delivery: RpcClient;
  currentKey: () => Promise<EpochPublicKey>;
  sourceIp: string | string[] | null;
  inboundHost?: string | null;
  anomalyFloor?: number;
  ips?: SourceIp[];
  publish?: (records: DomainRecord[]) => Promise<boolean>;
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

const publicKeyInfo = b.array(
  b.object({
    selector: b.string(),
    algorithm: b.enum(["rsa-sha256", "ed25519-sha256"]),
    publicKey: b.string(),
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

const TOUCH_MS = 60_000;
const SIGNER_DOMAINS_MS = 60_000;

export function coreMethods(deps: CoreDeps): {
  methods: Methods;
  verifyPending(): Promise<void>;
  enqueueInternal(from: string, to: string, data: string): Promise<string>;
} {
  const { db, writer, log, signer, delivery } = deps;
  const now = deps.now ?? Date.now;
  const startedAt = now();

  const touched = new Map<string, number>();
  const touch = (id: string) => {
    const t = now();
    if (t - (touched.get(id) ?? 0) < TOUCH_MS) return;
    touched.set(id, t);
    void writer.run((d) => touchKey(d, id, t), { quiet: true }).catch(() => {});
  };

  let signerDomains: { at: number; domains: Set<string> } | null = null;
  let fetchingDomains: Promise<Set<string>> | null = null;
  const fetchSignerDomains = (): Promise<Set<string>> => {
    fetchingDomains ??= signer
      .call("domains", {}, { result: b.array(b.string()) })
      .then((list) => {
        signerDomains = { at: now(), domains: new Set(list) };
        return signerDomains.domains;
      })
      .finally(() => {
        fetchingDomains = null;
      });
    return fetchingDomains;
  };
  const signerHasKeys = async (domain: string): Promise<boolean> => {
    const fresh = signerDomains !== null && now() - signerDomains.at < SIGNER_DOMAINS_MS;
    if (fresh && signerDomains?.domains.has(domain)) return true;
    return (await fetchSignerDomains()).has(domain);
  };

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
    touch(key.id);
    return key;
  };

  const prepareEnqueue = async (p: EnqueueInput, key: ApiKey) => {
    const id = p.id ?? Bun.randomUUIDv7();
    if (p.id !== undefined && emailExists(db, id)) return { id, existed: true as const };
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
    if (!(await signerHasKeys(headerDomain))) {
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
        return { id: prev.messageId, existed: true as const };
      }
    }
    const lane = (p.priority ?? 0) > 0 ? "bulk" : "transactional";
    if (lane === "bulk" && p.recipients.length !== 1) {
      throw new RpcError("invalid", "a bulk email must have exactly one recipient");
    }
    if (lane === "bulk") {
      const hold =
        activeHold(db, `domain:${headerDomain}`, "bulk") ??
        (key.id !== "operator" ? activeHold(db, `key:${key.id}`, "bulk") : null);
      if (hold) {
        throw new RpcError(
          "held",
          `Bulk sending is on hold (${hold.reason}). An operator must review and release it.`,
        );
      }
      if (key.id !== "operator") {
        const count = await writer.run((d) => countKeyBulk(d, key.id, 1, t));
        const threshold = anomalyThreshold(db, key.id, t, deps.anomalyFloor ?? 500);
        if (count > threshold) {
          const reason = `unusual volume: ${count} bulk emails this hour from API key ${key.prefix}…, normal is under ${threshold}`;
          const { created } = await writer.run((d) =>
            createHold(d, `key:${key.id}`, "bulk", reason, t),
          );
          if (created)
            log.error("bulk mail held for an API key: possible leaked key", {
              key: key.prefix,
              count,
              threshold,
            });
          throw new RpcError(
            "held",
            `Bulk sending is on hold (${reason}). An operator must review and release it.`,
          );
        }
      }
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
    return {
      id,
      existed: false as const,
      persist: (d: Database) => {
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
      },
    };
  };

  const enqueueFailed = (err: unknown): never => {
    if (err instanceof RpcError) throw err;
    if (err instanceof AddressError) throw new RpcError("invalid", err.message);
    throw new RpcError("invalid", (err as Error).message);
  };

  const changeable = (key: ApiKey, id: string) => {
    const email = MESSAGE_ID.test(id) ? scheduledEmail(db, id) : null;
    if (!email) throw new RpcError("not-found", "email not found");
    if (key.domains && !key.domains.includes(domainOf(email.from))) {
      throw new RpcError("forbidden", "this API key cannot change this email");
    }
    if (email.scheduledAt === null) {
      throw new RpcError("started", "Only a scheduled email can be canceled or changed.");
    }
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
        result: b.record(b.string(), b.array(b.string())),
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
    authenticate: method(b.object({ tokenHash: b.string() }), ({ tokenHash: hash }) => {
      const key = keyForHash(db, hash);
      if (!key) throw new RpcError("unauthenticated", "API key is invalid");
      return { id: key.id, scope: key.scope, domains: key.domains, rateLimit: key.rateLimit };
    }),

    enqueue: method(enqueueParams, async (p) => {
      const key = caller(p.tokenHash, "send");
      const r = await prepareEnqueue(p, key);
      if (r.existed) return { id: r.id, existed: true };
      try {
        return await writer.run((d) => r.persist(d));
      } catch (err) {
        if (!(err instanceof RpcError) && emailExists(db, r.id)) return { id: r.id, existed: true };
        return enqueueFailed(err);
      }
    }),

    enqueueBatch: method(
      b.object({
        tokenHash,
        emails: b
          .array(enqueueParams.omit({ tokenHash: true }))
          .min(1)
          .max(100),
      }),
      async (p) => {
        const key = caller(p.tokenHash, "send");
        const ready: Awaited<ReturnType<typeof prepareEnqueue>>[] = [];
        for (const [i, e] of p.emails.entries()) {
          try {
            ready.push(await prepareEnqueue(e, key));
          } catch (err) {
            if (err instanceof RpcError)
              throw new RpcError(err.code, `emails[${i}]: ${err.message}`);
            throw err;
          }
        }
        try {
          return {
            data: await writer.run((d) =>
              ready.map((r) => (r.existed ? { id: r.id, existed: true } : r.persist(d))),
            ),
          };
        } catch (err) {
          return enqueueFailed(err);
        }
      },
    ),

    getEmail: method(b.object({ tokenHash, id: b.string() }), ({ tokenHash: hash, id }) => {
      caller(hash, "read");
      if (!MESSAGE_ID.test(id)) throw new RpcError("not-found", "email not found");
      const view = emailView(db, id, now());
      if (!view) throw new RpcError("not-found", "email not found");
      return view;
    }),

    cancelEmail: method(b.object({ tokenHash, id: b.string() }), async (p) => {
      const key = caller(p.tokenHash, "send");
      changeable(key, p.id);
      const r = await writer.run((d) => cancelEmail(d, p.id, now()));
      if (r === "started") {
        throw new RpcError(
          "started",
          "This email has started sending and can no longer be canceled.",
        );
      }
      return { id: p.id };
    }),

    rescheduleEmail: method(
      b.object({ tokenHash, id: b.string(), scheduledAt: b.number().int().positive() }),
      async (p) => {
        const key = caller(p.tokenHash, "send");
        changeable(key, p.id);
        const t = now();
        if (p.scheduledAt > t + MAX_SCHEDULE_MS) {
          throw new RpcError("invalid", "scheduled_at can be at most 72 hours ahead");
        }
        const r = await writer.run((d) => rescheduleEmail(d, p.id, p.scheduledAt, t));
        if (r === "started") {
          throw new RpcError(
            "started",
            "This email has started sending and can no longer be changed.",
          );
        }
        if (r === "expires")
          throw new RpcError("invalid", "scheduled_at is after the email expires");
        return { id: p.id };
      },
    ),

    status: method(b.object({ id: b.string().regex(MESSAGE_ID) }), ({ id }) =>
      recipientsOf(db, id).map((r) => ({
        address: r.address,
        status: r.status,
        attempts: r.attempts,
        reply: r.reply,
        class: r.class,
      })),
    ),

    addDomain: method(b.object({ tokenHash, name: b.string().max(253) }), async (p) => {
      caller(p.tokenHash, "full");
      const name = domainName(p.name);
      const existing = getDomain(db, name);
      if (existing) return domainView(existing);
      const keys = await signer.call(
        "ensureKeys",
        { domain: name, selectorBase: selectorBase(now()) },
        { result: publicKeyInfo, timeoutMs: 60_000 },
      );
      signerDomains = null;
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
      if (deps.publish && (await deps.publish(d.records))) {
        await verify(name).catch(() => {});
      }
      return domainView(getDomain(db, name) as Domain);
    }),

    getDomain: method(b.object({ tokenHash, name: b.string().max(253) }), (p) => {
      caller(p.tokenHash, "read");
      const d = getDomain(db, domainName(p.name));
      if (!d) throw new RpcError("not-found", "domain not found");
      return domainView(d);
    }),

    listDomains: method(b.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      return listDomains(db).map(domainView);
    }),

    verifyDomain: method(b.object({ tokenHash, name: b.string().max(253) }), async (p) => {
      caller(p.tokenHash, "full");
      return domainView(await verify(domainName(p.name)));
    }),

    createKey: method(
      b.object({
        name: b.string().min(1).max(100),
        scope: b.enum(["send", "read", "full"]),
        domains: b.array(b.string().max(253)).max(100).optional(),
        rateLimit: b.number().int().min(1).max(10_000).optional(),
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

    listKeys: method(b.object({}), () => listKeys(db)),

    revokeKey: method(b.object({ id: b.string().min(1).max(64) }), async ({ id }) => {
      if (!(await writer.run((d) => revokeKey(d, id, now())))) {
        throw new RpcError("not-found", "no active key with that id");
      }
      return { id, revoked: true };
    }),

    health: method(b.object({}), () => ({ ok: true, jobs: countByState(db) })),

    ips: method(b.object({ tokenHash }), async (p) => {
      caller(p.tokenHash, "read");
      const reverse = await delivery
        .call<
          {
            ip: string;
            ehlo: string;
            ptr: string | null;
            forwardConfirmed: boolean;
            problem: string | null;
          }[]
        >("ips", {}, { timeoutMs: 5_000 })
        .catch(() => []);
      const warm = listWarmup(db);
      const today = dayOf(now());
      return (deps.ips ?? []).map((ip) => {
        const r = reverse.find((x) => x.ip === ip.ip);
        const rows = warm.filter((w) => w.ip === ip.ip);
        return {
          object: "ip",
          ip: ip.ip,
          pool: ip.pool,
          ehlo: r?.ehlo ?? null,
          ptr: r?.ptr ?? null,
          reverse_dns_ok: r?.forwardConfirmed ?? false,
          reverse_dns_problem: r?.problem ?? "unknown",
          warmup: ip.established
            ? { state: "established" }
            : {
                state:
                  rows.length === 0
                    ? "not started"
                    : rows.every((w) => w.state === "done")
                      ? "done"
                      : "warming",
                providers: rows.map((w) => {
                  const day = today - w.startedDay + 1;
                  return {
                    provider: w.provider,
                    state: w.state,
                    day,
                    of_about: w.state === "done" ? day : estimatedDays(w.budget, day),
                    budget_today: w.budget,
                    sent_today: w.day === today ? w.sent : 0,
                    last_days: w.history.slice(-7),
                  };
                }),
              },
          paths: (deps.paths?.() ?? [])
            .filter((v) => v.source === ip.ip)
            .map((v) => ({ destination: v.target, state: v.mode, rate_per_sec: v.rate })),
        };
      });
    }),

    holds: method(b.object({ tokenHash, all: b.boolean().default(false) }), (p) => {
      caller(p.tokenHash, "read");
      return {
        holds: listHolds(db, p.all).map((h) => ({
          object: "hold",
          id: h.id,
          target: h.target,
          lane: h.lane,
          reason: h.reason,
          created_at: new Date(h.createdAt).toISOString(),
          released_at: h.releasedAt === null ? null : new Date(h.releasedAt).toISOString(),
        })),
        senders: senderRates(db, now()).map((r) => ({
          domain: r.domain,
          lane: r.lane,
          delivered: r.delivered,
          hard_bounced: r.hardBounced,
          complained: r.complained,
          complaint_rate: Math.round(r.complaintRate * 100_000) / 1000,
          bounce_rate: Math.round(r.bounceRate * 100_000) / 1000,
        })),
      };
    }),

    releaseHold: method(b.object({ tokenHash, id: b.string().max(64) }), async (p) => {
      caller(p.tokenHash, "full");
      if (!(await writer.run((d) => releaseHold(d, p.id, now())))) {
        throw new RpcError("not-found", "no active hold with that id");
      }
      log.info("hold released", { id: p.id });
      return { id: p.id, released: true };
    }),

    queue: method(b.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      const q = queueSummary(db, now());
      return { ...q, suspensions: q.suspensions.map(suspensionView) };
    }),

    suspend: method(
      b.object({
        tokenHash,
        target: b.string().regex(SUSPEND_TARGET, "must be domain:NAME or provider:ID"),
        reason: b.string().min(1).max(500),
        until: b.number().int().positive().nullable().default(null),
      }),
      async (p) => {
        caller(p.tokenHash, "full");
        const t = now();
        if (p.until !== null && p.until <= t) throw new RpcError("invalid", "until is in the past");
        const s = await writer.run((d) => suspend(d, p.target, p.reason, p.until, t));
        log.warn("delivery suspended by an operator", { target: p.target, reason: p.reason });
        return suspensionView(s);
      },
    ),

    resume: method(b.object({ tokenHash, target: b.string().max(300) }), async (p) => {
      caller(p.tokenHash, "full");
      const r = await writer.run((d) => resume(d, p.target, now()));
      if (!r.resumed) throw new RpcError("not-found", `${p.target} is not suspended`);
      log.info("delivery resumed by an operator", { target: p.target, woken: r.woken });
      return { target: p.target, resumed: true, woken: r.woken };
    }),

    removeQueued: method(
      b.object({
        tokenHash,
        action: b.enum(["fail", "cancel"]),
        reason: b.string().min(1).max(500),
        domain: b.string().regex(DOMAIN).optional(),
        senderDomain: b.string().regex(DOMAIN).optional(),
        olderThanMs: b.number().int().nonnegative().optional(),
        dryRun: b.boolean().default(false),
      }),
      async (p) => {
        caller(p.tokenHash, "full");
        const filter = {
          ...(p.domain !== undefined ? { domain: p.domain } : {}),
          ...(p.senderDomain !== undefined ? { senderDomain: p.senderDomain } : {}),
          ...(p.olderThanMs !== undefined ? { olderThanMs: p.olderThanMs } : {}),
        };
        if (Object.keys(filter).length === 0) {
          throw new RpcError("invalid", "give at least one filter: domain, sender domain or age");
        }
        const r = await writer.run((d) =>
          removeQueued(d, filter, p.action, p.reason, now(), p.dryRun),
        );
        if (!p.dryRun && r.jobs > 0) {
          log.warn(`queued email ${p.action === "cancel" ? "canceled" : "failed"} by an operator`, {
            ...filter,
            reason: p.reason,
            emails: r.emails,
          });
        }
        return {
          dry_run: p.dryRun,
          emails: r.emails,
          recipients: r.recipients,
          skipped_sending: r.skippedSending,
        };
      },
    ),

    metrics: method(b.object({ tokenHash }), (p) => {
      caller(p.tokenHash, "read");
      return { text: render(collect(db, deps.paths?.() ?? [], now(), startedAt)) };
    }),

    paths: method(b.object({ tokenHash }), (p) => {
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
  const enqueueInternal = async (from: string, to: string, data: string): Promise<string> => {
    const r = await prepareEnqueue(
      {
        from,
        recipients: [to],
        data,
        smtpUtf8: false,
        requireTls: false,
        meta: { from, to: [to], cc: [], bcc: [], replyTo: [], tags: [], lane: "transactional" },
      },
      OPERATOR,
    );
    if (r.existed) return r.id;
    return (await writer.run((d) => r.persist(d))).id;
  };

  return { methods, verifyPending, enqueueInternal };
}
