import type { Database } from "bun:sqlite";
import {
  createKey,
  keyForHash,
  listKeys,
  revokeKey,
  type Scope,
  touchKey,
} from "../accounts/api-keys.ts";
import { findProject, projectOfMessage, SYSTEM_PROJECT } from "../accounts/projects.ts";
import { type Over, takeQuota } from "../accounts/usage.ts";
import type { SourceIp } from "../config.ts";
import { appendEvent } from "../core/events.ts";
import { countByState } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import type { StorageState } from "../core/storage.ts";
import type { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, sealBody } from "../crypto/envelope.ts";
import {
  cancelEmail,
  enqueueEmail,
  recipientsOf,
  rescheduleEmail,
  scheduledEmail,
} from "../delivery/queue.ts";
import { suppressedAtIntake } from "../delivery/simulator.ts";
import {
  allDomains,
  type Domain,
  type DomainRecord,
  domainPool,
  evaluate,
  expectedRecords,
  findDomain,
  getDomain,
  listDomains,
  saveDomain,
  setDomainPool,
} from "../domains/domains.ts";
import { findIdempotent, rememberIdempotent } from "../emails/idempotency.ts";
import { METRICS, searchEmails, statsFor } from "../emails/search.ts";
import { emailSummary, emailView } from "../emails/view.ts";
import { latestPostmaster } from "../guards/gmail.ts";
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
import {
  type Actor,
  type Auth,
  type Caller,
  requireServerWide,
  resolveActor,
  resolveServer,
  scopeOf,
} from "./actor.ts";
import { domainName, knownPool } from "./checks.ts";
import { DOMAIN, enqueueParams, MESSAGE_ID, project, tokenHash } from "./wire.ts";

const SUSPEND_TARGET =
  /^(domain:(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}|provider:[a-z0-9-]{1,40})$/;

const suspensionView = (s: Suspension) => ({
  target: s.target,
  reason: s.reason,
  until: s.until === null ? null : new Date(s.until).toISOString(),
  since: new Date(s.createdAt).toISOString(),
});

type EnqueueInput = Omit<b.output<typeof enqueueParams>, "tokenHash" | "project">;

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
  anomalyFloor?: () => number;
  ips?: SourceIp[];
  tracking?: (domain: string) => unknown;
  scan?: (data: string, from: string, recipients: string[]) => Promise<void>;
  hasCheckHooks?: () => boolean;
  publish?: (records: DomainRecord[]) => Promise<boolean>;
  paths?: () => PathView[];
  storage?: () => StorageState;
  now?: () => number;
}

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

  const caller = (auth: Auth, needed: Scope): Actor => {
    const actor = resolveActor(db, auth, needed);
    if (actor.key) touch(actor.key.id);
    return actor;
  };
  const server = (auth: Auth, needed: Scope): Caller => {
    const c = resolveServer(db, auth, needed);
    if (c.key) touch(c.key.id);
    return c;
  };

  const prepareEnqueue = async (p: EnqueueInput, actor: Actor) => {
    const { project, key } = actor;
    const storage = deps.storage?.();
    if (storage?.low) {
      throw new RpcError(
        "storage-low",
        `free disk space is below ${storage.minFreeMb} MB; new email is accepted again once space is freed`,
      );
    }
    const settings = findProject(db, project);
    if (settings?.suspendedAt != null) {
      throw new RpcError(
        "project-suspended",
        "This project is suspended. Sending is paused until it is resumed.",
      );
    }
    const limits = { perHour: settings?.perHour ?? null, perDay: settings?.perDay ?? null };
    const id = p.id ?? Bun.randomUUIDv7();
    if (p.id !== undefined) {
      const owner = projectOfMessage(db, id);
      if (owner === project) return { id, existed: true as const };
      if (owner !== null) throw new RpcError("invalid", "this email id is already used");
    }
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
    if (key?.domains && !key.domains.includes(headerDomain)) {
      throw new RpcError("forbidden", `this API key cannot send from ${headerDomain}`);
    }
    const domain =
      project === SYSTEM_PROJECT
        ? findDomain(db, headerDomain)
        : getDomain(db, project, headerDomain);
    if (domain?.status !== "verified" && !(key?.test && domain)) {
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
    const idemOwner = key?.id ?? `operator:${project}`;
    if (idem) {
      const prev = findIdempotent(db, idemOwner, idem.key, t);
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
        (key ? activeHold(db, `key:${key.id}`, "bulk") : null);
      if (hold) {
        throw new RpcError(
          "held",
          `Bulk sending is on hold (${hold.reason}). An operator must review and release it.`,
        );
      }
      if (key) {
        const count = await writer.run((d) => countKeyBulk(d, key.id, 1, t));
        const threshold = anomalyThreshold(db, key.id, t, deps.anomalyFloor?.() ?? 500);
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
    const sending = new Set<string>();
    for (const raw of p.recipients) {
      let address: string;
      try {
        address = normalizeAddress(raw);
      } catch (err) {
        throw new RpcError("invalid", (err as Error).message);
      }
      const s = suppressedAtIntake(address)
        ? { reason: "simulated", scope: "all" }
        : suppressionFor(db, project, address, lane, t);
      if (s) suppressed.set(address, { reason: s.reason, scope: s.scope });
      else sending.add(address);
    }
    const counted = key?.test ? 0 : sending.size;
    await deps.scan?.(p.data, envelopeFrom, p.recipients);
    const body = await sealBody(await deps.currentKey(), id, p.data);
    return {
      id,
      existed: false as const,
      persist: (d: Database) => {
        if (idem) {
          const prev = findIdempotent(d, idemOwner, idem.key, t);
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
        const quota = takeQuota(d, project, limits, counted, t);
        if (!quota.ok) throw limitError(quota.over);
        enqueueEmail(
          d,
          project,
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
              apiKeyId: key?.id ?? null,
              scheduledAt: p.scheduledAt ?? null,
              ...(key?.test ? { test: true } : {}),
              ...((key?.pool ?? domainPool(db, headerDomain))
                ? { pool: key?.pool ?? domainPool(db, headerDomain) }
                : {}),
            },
            ...(p.expiresAt !== undefined ? { expiresAt: p.expiresAt } : {}),
            ...(p.scheduledAt !== undefined ? { runAfter: p.scheduledAt } : {}),
            ...(p.priority !== undefined ? { priority: p.priority } : {}),
          },
          t,
        );
        if (idem) rememberIdempotent(d, idemOwner, idem.key, idem.hash, id, t);
        for (const near of quota.near) {
          appendEvent(d, {
            messageId: id,
            kind: "limit_approaching",
            source: "intake",
            at: t,
            data: { window: near.window, limit: near.limit, used: near.used },
          });
        }
        return { id, existed: false };
      },
    };
  };

  const limitError = (o: Over): RpcError => {
    const span = o.window === "hour" ? "hourly" : "daily";
    if (o.retryAfterMs === null) {
      return new RpcError(
        "invalid",
        `this email has more recipients than the project's ${span} limit of ${o.limit}`,
      );
    }
    const seconds = Math.ceil(o.retryAfterMs / 1000);
    return new RpcError(
      "project-limit",
      `The project's ${span} limit of ${o.limit} recipients is reached. Try again in ${seconds} seconds.`,
      seconds,
    );
  };

  const enqueueFailed = (err: unknown): never => {
    if (err instanceof RpcError) throw err;
    if (err instanceof AddressError) throw new RpcError("invalid", err.message);
    throw new RpcError("invalid", (err as Error).message);
  };

  const changeable = ({ project, key }: Actor, id: string) => {
    const email = MESSAGE_ID.test(id) ? scheduledEmail(db, project, id) : null;
    if (!email) throw new RpcError("not-found", "email not found");
    if (key?.domains && !key.domains.includes(domainOf(email.from))) {
      throw new RpcError("forbidden", "this API key cannot change this email");
    }
    if (email.scheduledAt === null) {
      throw new RpcError("started", "Only a scheduled email can be canceled or changed.");
    }
  };

  const verify = async (project: Actor["project"], name: string): Promise<Domain> => {
    const d = getDomain(db, project, name);
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
    for (const d of allDomains(db).filter((x) => x.status === "pending")) {
      try {
        await verify(d.project, d.name);
      } catch (err) {
        log.warn("could not check domain", { domain: d.name, error: (err as Error).message });
      }
    }
  };

  const methods: Methods = {
    authenticate: method(b.object({ tokenHash: b.string() }), ({ tokenHash: hash }) => {
      const key = keyForHash(db, hash);
      if (!key) throw new RpcError("unauthenticated", "API key is invalid");
      return {
        id: key.id,
        scope: key.scope,
        domains: key.domains,
        rateLimit: key.rateLimit,
        hooks: deps.hasCheckHooks?.() ?? false,
      };
    }),

    enqueue: method(enqueueParams, async (p) => {
      const actor = caller(p, "send");
      const r = await prepareEnqueue(p, actor);
      if (r.existed) return { id: r.id, existed: true };
      try {
        return await writer.run((d) => r.persist(d));
      } catch (err) {
        if (!(err instanceof RpcError) && projectOfMessage(db, r.id) === actor.project) {
          return { id: r.id, existed: true };
        }
        return enqueueFailed(err);
      }
    }),

    enqueueBatch: method(
      b.object({
        tokenHash,
        project,
        emails: b
          .array(enqueueParams.omit({ tokenHash: true, project: true }))
          .min(1)
          .max(100),
      }),
      async (p) => {
        const actor = caller(p, "send");
        const ready: Awaited<ReturnType<typeof prepareEnqueue>>[] = [];
        for (const [i, e] of p.emails.entries()) {
          try {
            ready.push(await prepareEnqueue(e, actor));
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

    getEmail: method(b.object({ tokenHash, project, id: b.string() }), (p) => {
      const { project } = caller(p, "read");
      const { id } = p;
      if (!MESSAGE_ID.test(id)) throw new RpcError("not-found", "email not found");
      const view = emailView(db, project, id, now());
      if (!view) throw new RpcError("not-found", "email not found");
      return view;
    }),

    listEmails: method(
      b.object({
        tokenHash,
        project,
        limit: b.number().int().min(1).max(100),
        before: b.string().regex(MESSAGE_ID).optional(),
        to: b.string().max(320).optional(),
        status: b
          .enum(["queued", "deferred", "unknown", "delivered", "bounced", "failed"])
          .optional(),
        tag: b.string().max(512).optional(),
        domain: b.string().max(253).optional(),
        since: b.number().int().optional(),
        until: b.number().int().optional(),
      }),
      (p) => {
        const { project } = caller(p, "read");
        const ids = searchEmails(db, project, {
          limit: p.limit + 1,
          before: p.before,
          to: p.to?.toLowerCase(),
          status: p.status,
          tag: p.tag,
          domain: p.domain?.toLowerCase(),
          since: p.since,
          until: p.until,
        });
        const page = ids.slice(0, p.limit);
        return {
          data: page.flatMap((id) => {
            const s = emailSummary(db, project, id, now());
            return s ? [s] : [];
          }),
          next_cursor: ids.length > p.limit ? (page.at(-1) ?? null) : null,
        };
      },
    ),

    stats: method(
      b.object({
        tokenHash,
        project,
        since: b.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        until: b.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        domain: b.string().max(253).optional(),
        tag: b.string().max(512).optional(),
      }),
      (p) => {
        const { project } = caller(p, "read");
        const days = (Date.parse(p.until) - Date.parse(p.since)) / 86_400_000;
        if (!(days >= 0 && days <= 400)) {
          throw new RpcError("invalid", "since must be before until, at most 400 days apart");
        }
        const data = statsFor(db, project, {
          since: p.since,
          until: p.until,
          domain: p.domain?.toLowerCase(),
          tag: p.tag,
        });
        const totals = Object.fromEntries(
          METRICS.map((m) => [m, data.reduce((n, d) => n + d[m], 0)]),
        );
        return { object: "stats", since: p.since, until: p.until, totals, data };
      },
    ),

    cancelEmail: method(b.object({ tokenHash, project, id: b.string() }), async (p) => {
      const actor = caller(p, "send");
      changeable(actor, p.id);
      const r = await writer.run((d) => cancelEmail(d, actor.project, p.id, now()));
      if (r === "started") {
        throw new RpcError(
          "started",
          "This email has started sending and can no longer be canceled.",
        );
      }
      return { id: p.id };
    }),

    rescheduleEmail: method(
      b.object({ tokenHash, project, id: b.string(), scheduledAt: b.number().int().positive() }),
      async (p) => {
        const actor = caller(p, "send");
        changeable(actor, p.id);
        const t = now();
        if (p.scheduledAt > t + MAX_SCHEDULE_MS) {
          throw new RpcError("invalid", "scheduled_at can be at most 72 hours ahead");
        }
        const r = await writer.run((d) =>
          rescheduleEmail(d, actor.project, p.id, p.scheduledAt, t),
        );
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

    addDomain: method(b.object({ tokenHash, project, name: b.string().max(253) }), async (p) => {
      const { project } = caller(p, "full");
      const name = domainName(p.name);
      const existing = findDomain(db, name);
      if (existing && existing.project !== project) {
        throw new RpcError("domain-taken", `${name} is already added on this server`);
      }
      if (existing) return domainView(existing);
      const keys = await signer.call(
        "ensureKeys",
        { domain: name, selectorBase: selectorBase(now()) },
        { result: publicKeyInfo, timeoutMs: 60_000 },
      );
      signerDomains = null;
      const t = now();
      const d: Domain = {
        project,
        name,
        status: "pending",
        records: expectedRecords(name, keys, deps.sourceIp, deps.inboundHost ?? null),
        createdAt: t,
        checkedAt: null,
      };
      await writer.run((w) => {
        if (!findDomain(w, name)) saveDomain(w, d, t);
      });
      log.info("domain added", { domain: name });
      if (deps.publish && (await deps.publish(d.records))) {
        await verify(project, name).catch(() => {});
      }
      const added = getDomain(db, project, name);
      if (!added) throw new RpcError("domain-taken", `${name} is already added on this server`);
      return domainView(added);
    }),

    setDomainPool: method(
      b.object({
        tokenHash,
        project,
        name: b.string().max(253),
        pool: b.string().max(32).nullable(),
      }),
      async (p) => {
        const { project } = caller(p, "full");
        if (p.pool !== null) knownPool(deps.ips, p.pool);
        const name = domainName(p.name);
        if (!(await writer.run((d) => setDomainPool(d, project, name, p.pool, now())))) {
          throw new RpcError("not-found", "domain not found");
        }
        return { name, ip_pool: p.pool };
      },
    ),

    getDomain: method(b.object({ tokenHash, project, name: b.string().max(253) }), (p) => {
      const { project } = caller(p, "read");
      const d = getDomain(db, project, domainName(p.name));
      if (!d) throw new RpcError("not-found", "domain not found");
      const gmail = latestPostmaster(db, d.name);
      return {
        ...domainView(d),
        ip_pool: domainPool(db, d.name),
        tracking: deps.tracking?.(d.name) ?? null,
        gmail: gmail
          ? {
              day: gmail.day,
              spam_rate: gmail.spamRatio,
              reputation: gmail.reputation,
              spf_pass_rate: gmail.spfRatio,
              dkim_pass_rate: gmail.dkimRatio,
              dmarc_pass_rate: gmail.dmarcRatio,
              tls_rate: gmail.encryptedRatio,
            }
          : null,
      };
    }),

    listDomains: method(b.object({ tokenHash, project }), (p) => {
      const { project } = caller(p, "read");
      return listDomains(db, project).map(domainView);
    }),

    verifyDomain: method(b.object({ tokenHash, project, name: b.string().max(253) }), async (p) => {
      const { project } = caller(p, "full");
      return domainView(await verify(project, domainName(p.name)));
    }),

    health: method(b.object({}), () => ({ ok: true, jobs: countByState(db) })),

    ips: method(b.object({ tokenHash, project }), async (p) => {
      server(p, "read");
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

    holds: method(b.object({ tokenHash, project, all: b.boolean().default(false) }), (p) => {
      const scope = scopeOf(server(p, "read"));
      return {
        holds: listHolds(db, scope, p.all).map((h) => ({
          object: "hold",
          id: h.id,
          target: h.target,
          lane: h.lane,
          reason: h.reason,
          created_at: new Date(h.createdAt).toISOString(),
          released_at: h.releasedAt === null ? null : new Date(h.releasedAt).toISOString(),
        })),
        senders: senderRates(db, scope, now()).map((r) => ({
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

    releaseHold: method(b.object({ tokenHash, project, id: b.string().max(64) }), async (p) => {
      const scope = scopeOf(server(p, "full"));
      if (!(await writer.run((d) => releaseHold(d, scope, p.id, now())))) {
        throw new RpcError("not-found", "no active hold with that id");
      }
      log.info("hold released", { id: p.id });
      return { id: p.id, released: true };
    }),

    queue: method(b.object({ tokenHash, project }), (p) => {
      const q = queueSummary(db, scopeOf(server(p, "read")), now());
      return { ...q, suspensions: q.suspensions.map(suspensionView) };
    }),

    suspend: method(
      b.object({
        tokenHash,
        project,
        target: b.string().regex(SUSPEND_TARGET, "must be domain:NAME or provider:ID"),
        reason: b.string().min(1).max(500),
        until: b.number().int().positive().nullable().default(null),
      }),
      async (p) => {
        requireServerWide(db, server(p, "full"));
        const t = now();
        if (p.until !== null && p.until <= t) throw new RpcError("invalid", "until is in the past");
        const s = await writer.run((d) => suspend(d, p.target, p.reason, p.until, t));
        log.warn("delivery suspended by an operator", { target: p.target, reason: p.reason });
        return suspensionView(s);
      },
    ),

    resume: method(b.object({ tokenHash, project, target: b.string().max(300) }), async (p) => {
      requireServerWide(db, server(p, "full"));
      const r = await writer.run((d) => resume(d, p.target, now()));
      if (!r.resumed) throw new RpcError("not-found", `${p.target} is not suspended`);
      log.info("delivery resumed by an operator", { target: p.target, woken: r.woken });
      return { target: p.target, resumed: true, woken: r.woken };
    }),

    removeQueued: method(
      b.object({
        tokenHash,
        project,
        action: b.enum(["fail", "cancel"]),
        reason: b.string().min(1).max(500),
        domain: b.string().regex(DOMAIN).optional(),
        senderDomain: b.string().regex(DOMAIN).optional(),
        olderThanMs: b.number().int().nonnegative().optional(),
        dryRun: b.boolean().default(false),
      }),
      async (p) => {
        const scope = scopeOf(server(p, "full"));
        const filter = {
          ...(p.domain !== undefined ? { domain: p.domain } : {}),
          ...(p.senderDomain !== undefined ? { senderDomain: p.senderDomain } : {}),
          ...(p.olderThanMs !== undefined ? { olderThanMs: p.olderThanMs } : {}),
        };
        if (Object.keys(filter).length === 0) {
          throw new RpcError("invalid", "give at least one filter: domain, sender domain or age");
        }
        const r = await writer.run((d) =>
          removeQueued(d, scope, filter, p.action, p.reason, now(), p.dryRun),
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

    metrics: method(b.object({ tokenHash, project }), (p) => {
      const scope = scopeOf(server(p, "read"));
      return {
        text: render(collect(db, scope, deps.paths?.() ?? [], now(), startedAt, deps.storage?.())),
      };
    }),

    paths: method(b.object({ tokenHash, project }), (p) => {
      server(p, "read");
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
      { kind: "operator", project: SYSTEM_PROJECT, key: null },
    );
    if (r.existed) return r.id;
    return (await writer.run((d) => r.persist(d))).id;
  };

  return { methods, verifyPending, enqueueInternal };
}
