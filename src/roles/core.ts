import { choosePool } from "../accounts/pool-rules.ts";
import { recordAdminEvent, SYSTEM_PROJECT } from "../accounts/projects.ts";
import { purgeDeletedProject } from "../accounts/purge.ts";
import {
  finishSeed,
  pruneRecipients,
  type RecipientHash,
  recipientHasher,
  recipientsSeeded,
  rememberRecipients,
  seedPage,
} from "../accounts/recipients.ts";
import { pruneUsage } from "../accounts/usage.ts";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { fail, type Outcome } from "../core/outcome.ts";
import { defaultRetryPolicy, type RetryPolicy } from "../core/retry.ts";
import { StorageWatch } from "../core/storage.ts";
import { openDatabase } from "../core/store/db.ts";
import { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, epochOf } from "../crypto/envelope.ts";
import { deliveryHandler } from "../delivery/handler.ts";
import { cachingLookups } from "../delivery/lookups.ts";
import { shredBodies } from "../delivery/queue.ts";
import type { DeliveryTransport } from "../delivery/transport.ts";
import { pruneDmarc } from "../dmarc/store.ts";
import { isSlot } from "../domains/delegated.ts";
import {
  allDomains,
  bounceDomain,
  findDomain,
  type PublicDkimKey,
  returnPathReady,
  zoneDomainNames,
} from "../domains/domains.ts";
import { pruneIdempotency } from "../emails/idempotency.ts";
import { pruneConversations } from "../emails/view.ts";
import { beginAtEnd, exportEvents } from "../eventlog/export.ts";
import { EventLog } from "../eventlog/log.ts";
import { gmailGuard, savePostmaster } from "../guards/gmail.ts";
import { reputationGuard } from "../guards/guards.ts";
import { pruneRouted } from "../inbound/routes.ts";
import { RpcClient, serveRpc } from "../ipc/rpc.ts";
import { rollover } from "../ips/warmup.ts";
import { DeliveryFleet, LOCAL } from "../nodes/fleet.ts";
import { CoreIdentity } from "../nodes/identity.ts";
import { NodeLinks } from "../nodes/links.ts";
import type { Span } from "../otel/otlp.ts";
import { expireSuspensions } from "../queue/control.ts";
import { Scheduler } from "../scheduler/scheduler.ts";
import { type ControlState, DEFAULT_TUNING } from "../shaping/control.ts";
import { Shaper } from "../shaping/shaper.ts";
import { sendTlsReports } from "../tlsrpt/job.ts";
import { b } from "../validate/schema.ts";
import { adminSocket } from "./admin-socket.ts";
import { apiMethods, inboundMethods } from "./core-access.ts";
import { coreMethods } from "./core-api.ts";
import { doctorMethods, ipInfo } from "./core-doctor.ts";
import { feedbackMethods } from "./core-feedback.ts";
import { hookMethods } from "./core-hooks.ts";
import { nodeMethods } from "./core-nodes.ts";
import { delegationCheck, nsProbe } from "./core-ns.ts";
import { projectMethods } from "./core-projects.ts";
import { OVERLAP_DAYS, rotation } from "./core-rotation.ts";
import { routeMethods } from "./core-routes.ts";
import { telemetry } from "./core-telemetry.ts";
import { templateMethods } from "./core-templates.ts";
import { trackingMethods } from "./core-tracking.ts";
import { delegatedDomains, zonePublisher } from "./core-zone.ts";
import { every, onStop, privateDir, ready } from "./runtime.ts";
import {
  deliveryReportWire,
  destinationWire,
  epochKeyFromWire,
  epochKeyWire,
  requestToWire,
  sockets,
} from "./wire.ts";

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const MAX_SETTLED = 50_000;

export function leaseTimes(scale: number): { leaseMs: number; maxWaitMs: number } {
  const leaseMs = Math.max(2_000, Math.max(1, Math.round(45 * MIN * scale)));
  return { leaseMs, maxWaitMs: Math.max(1_000, Math.floor(leaseMs / 3)) };
}

export function scaledPolicy(p: RetryPolicy, scale: number): RetryPolicy {
  const s = (ms: number) => Math.max(1, Math.round(ms * scale));
  return {
    ...p,
    stepsMs: p.stepsMs.map(s),
    everyMs: s(p.everyMs),
    maxAgeMs: s(p.maxAgeMs),
    noticesMs: p.noticesMs.map(s),
  };
}

export async function runCore(config: Config, log: Logger) {
  const scale = config.retryScale;
  const scaled = (ms: number) => Math.max(1, Math.round(ms * scale));
  await privateDir(config.dataDir);
  const db = openDatabase({ path: config.dbPath });
  const writer = new Writer(db);
  const eventLog = config.eventLog ? new EventLog(config.eventLog) : null;
  if (eventLog && config.eventLog) {
    await privateDir(config.eventLog.dir, "750");
    await eventLog.start(Date.now());
    await writer.run((d) => beginAtEnd(d, Date.now()));
  }
  const sock = sockets(config.runDir);
  const signer = new RpcClient(sock.signer);
  const delivery = new RpcClient(sock.delivery);
  const dns = new RpcClient(sock.dns);
  const ns = config.ns ? new RpcClient(sock.ns) : null;

  const identity = await CoreIdentity.load(`${config.dataDir}/node-link`, signer, Date.now());
  const links = new NodeLinks({ db, writer, log, signer, identity });
  const fleet = new DeliveryFleet({ local: delivery, links, log });
  await fleet.check();

  const settled = new Map<string, string[]>();
  const sentTo = new Map<string, string>();
  const takeSettled = (name: string) => settled.get(name)?.splice(0, 5000) ?? [];
  const putBack = (name: string, keys: string[]) =>
    settled.set(name, keys.concat(settled.get(name) ?? []));
  const transport: DeliveryTransport = cachingLookups({
    lookup: (domain) =>
      delivery.call("lookup", { domain }, { result: destinationWire, timeoutMs: 2 * MIN }),
    deliver: (req) => {
      const { name, client } = fleet.clientFor(req.source ?? "");
      const keys = takeSettled(name);
      sentTo.set(req.key, name);
      if (sentTo.size > MAX_SETTLED) sentTo.delete(sentTo.keys().next().value as string);
      return client
        .call("deliver", requestToWire({ ...req, ...(keys.length ? { settled: keys } : {}) }), {
          result: deliveryReportWire,
          timeoutMs: 40 * MIN,
        })
        .then((report) => {
          fleet.delivered(name, report.recipients.filter((r) => r.status === "delivered").length);
          return report;
        })
        .catch((err) => {
          putBack(name, keys);
          if ((err as { code?: unknown })?.code === "unavailable") {
            fleet.markDown(name, (err as Error).message);
          }
          throw err;
        });
    },
    forget: (keys) => {
      for (const key of keys) {
        const name = sentTo.get(key) ?? LOCAL;
        sentTo.delete(key);
        const list = settled.get(name) ?? [];
        list.push(key);
        if (list.length > MAX_SETTLED) list.splice(0, list.length - MAX_SETTLED);
        settled.set(name, list);
      }
    },
  });
  const flushSettled = async () => {
    for (const name of [...settled.keys()]) {
      const keys = takeSettled(name);
      if (keys.length === 0) continue;
      const client = fleet.client(name);
      if (!client) continue;
      try {
        await client.call("forget", { keys }, { timeoutMs: 10_000 });
      } catch {
        putBack(name, keys);
      }
    }
  };
  const restore = new Map(
    db
      .query<{ key: string; state: string }, []>("SELECT key, state FROM paths")
      .all()
      .map((r) => [r.key, JSON.parse(r.state) as ControlState]),
  );
  const shaper = new Shaper({
    log,
    tuning: {
      ...DEFAULT_TUNING,
      holdMs: scaled(DEFAULT_TUNING.holdMs),
      firstPauseMs: scaled(DEFAULT_TUNING.firstPauseMs),
      maxPauseMs: scaled(DEFAULT_TUNING.maxPauseMs),
    },
    restore,
    onChange: (key, state) => {
      void writer
        .run((d) =>
          d
            .query<unknown, [string, string, number]>(
              `INSERT INTO paths (key, state, updated_at) VALUES (?, ?, ?)
               ON CONFLICT (key) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`,
            )
            .run(key, JSON.stringify(state), Date.now()),
        )
        .catch((err: Error) => log.error("could not save path state", { error: err.message }));
    },
  });
  const listed = new Set<string>();
  const refreshListed = () =>
    delivery
      .call("ips", {}, { result: ipInfo, timeoutMs: 10_000 })
      .then((ips) => {
        listed.clear();
        for (const ip of ips) {
          if (ip.listings?.some((l) => l.status === "listed")) listed.add(ip.ip);
        }
      })
      .catch(() => {});
  const storage = new StorageWatch(config.dataDir, () => config.minFreeMb, log);
  await storage.check();
  const handleEmail = deliveryHandler({
    db,
    log,
    transport,
    shaper,
    busyRetryMs: scaled(MIN),
    ips: config.sourceIps,
    holdRetryMs: scaled(15 * MIN),
    suspendRetryMs: scaled(5 * MIN),
    maxWaitMs: leaseTimes(scale).maxWaitMs,
    bounceDomainFor: (d) => (returnPathReady(findDomain(db, d)) ? bounceDomain(d) : null),
    relayRoutes: () =>
      config.relay && !config.relay.for.all
        ? { targets: config.relay.for.targets, blocked: config.relay.for.blocked }
        : null,
    listed: (ip) => listed.has(ip),
    ipDown: (ip) => fleet.down(ip),
    nodeOf: (source) => fleet.nodeOf(source),
    poolRules: (job) =>
      choosePool(db, job, (pool) => config.sourceIps.some((x) => x.pool === pool)),
  });
  const scheduler = new Scheduler({
    db,
    writer,
    log,
    handle: (job, signal, ctx): Promise<Outcome> =>
      job.type === "email"
        ? handleEmail(job, signal, ctx)
        : Promise.resolve(fail("unknown-type", `no handler for ${job.type}`)),
    retry: scaledPolicy(defaultRetryPolicy, scale),
    reconcileMs: scaled(15 * MIN),
    leaseMs: leaseTimes(scale).leaseMs,
    concurrency: 512,
    filter: () => shaper.blocked(),
  });

  let epochKey: EpochPublicKey | null = null;
  let fetching: Promise<EpochPublicKey> | null = null;
  const currentKey = async (): Promise<EpochPublicKey> => {
    if (epochKey && epochKey.epoch === epochOf(Date.now())) return epochKey;
    fetching ??= signer
      .call("epochKey", {}, { result: epochKeyWire })
      .then((k) => {
        epochKey = epochKeyFromWire(k);
        return epochKey;
      })
      .finally(() => {
        fetching = null;
      });
    return fetching;
  };

  let hashing: Promise<RecipientHash> | null = null;
  const recipientHash: RecipientHash = async (address) => {
    hashing ??= signer
      .call("recipientKey", {}, { result: b.string() })
      .then((k) => recipientHasher(Uint8Array.fromBase64(k)))
      .catch((err: unknown) => {
        hashing = null;
        throw err;
      });
    return (await hashing)(address);
  };

  const hooks = hookMethods({ db, writer, log, delivery });
  const zone =
    config.ns && ns
      ? zonePublisher({
          ns,
          zone: config.ns.zone,
          ttl: config.ns.ttl,
          sourceIps: config.sourceIps.map((x) => x.ip),
          inboundHost: config.inboundHostname,
          domains: delegatedDomains({
            names: () => zoneDomainNames(db),
            keys: (domain) => rotate.keys(domain),
          }),
          log,
        })
      : null;
  const probe =
    config.ns && ns && zone
      ? nsProbe({
          measure: (server) =>
            delivery.call(
              "nsProbe",
              { ...server, zone: config.ns?.zone ?? "" },
              {
                timeoutMs: 10_000,
                result: b.object({
                  udp: b.number().nullable(),
                  tcp: b.number().nullable(),
                  served: b.number().nullable(),
                }),
              },
            ),
          targets: () =>
            ns.call(
              "listeners",
              {},
              {
                timeoutMs: 5_000,
                result: b.array(b.object({ host: b.string(), port: b.number().int() })),
              },
            ),
          pushed: () => zone.pushed(),
          raise: (kind, data) =>
            writer.run((w) =>
              recordAdminEvent(
                w,
                { kind, project: SYSTEM_PROJECT, actor: "core", data },
                Date.now(),
              ),
            ),
          log,
        })
      : null;
  const delegation =
    config.ns && zone
      ? delegationCheck({
          zone: config.ns.zone,
          names: config.ns.names,
          listen: config.ns.listen,
          lookup: (z) =>
            delivery.call(
              "nsDelegation",
              { zone: z },
              {
                timeoutMs: 60_000,
                result: b.object({
                  parent: b.string().nullable(),
                  asked: b.string().nullable(),
                  ns: b.array(b.string()),
                  glue: b.record(b.string(), b.array(b.string())),
                  addresses: b.record(b.string(), b.array(b.string())),
                  error: b.string().nullable(),
                }),
              },
            ),
          raise: (kind, data) =>
            writer.run((w) =>
              recordAdminEvent(
                w,
                { kind, project: SYSTEM_PROJECT, actor: "core", data },
                Date.now(),
              ),
            ),
          log,
        })
      : null;
  const zoneServes = (domain: string, keys: PublicDkimKey[]) => {
    const pushed = zone?.pushed();
    return (
      !zone ||
      !probe ||
      (!!pushed && zone.holds(domain, keys) && probe.servesAtLeast(pushed.serial))
    );
  };
  let spanSink: ((s: Span) => void) | null = null;
  const api = coreMethods({
    ...(config.otlp ? { span: (s: Span) => spanSink?.(s) } : {}),
    db,
    writer,
    log,
    signer,
    delivery,
    currentKey,
    recipientHash,
    sourceIp: config.sourceIps.map((x) => x.ip),
    inboundHost: config.inboundHostname,
    nsZone: config.ns?.zone ?? null,
    anomalyFloor: () => config.anomalyFloor,
    sharedBounces: () => config.sharedBounces,
    ips: config.sourceIps,
    relay: config.relay !== null,
    paths: () => shaper.views(),
    storage: () => storage.state(),
    nsHealth: () => probe?.view() ?? null,
    nsDelegation: () => delegation?.view() ?? null,
    nodes: () => fleet.health(),
    ...(config.ns && zone
      ? {
          nsCheck: async () => {
            const [listeners, view] = await Promise.all([
              probe ? probe.tick().then(() => probe.view()) : [],
              delegation ? delegation.check() : null,
            ]);
            const domains = await Promise.all(
              zoneDomainNames(db).map(async (name) => ({
                name,
                slots: (await rotate.keys(name).catch(() => []))
                  .filter((k) => isSlot(k.selector))
                  .map((k) => ({
                    selector: k.selector,
                    state: k.state,
                    emptiedFrom:
                      k.state === "retiring" && k.retiringSince !== null
                        ? k.retiringSince + OVERLAP_DAYS * DAY
                        : null,
                  })),
              })),
            );
            return {
              zone: config.ns?.zone ?? "",
              serial: zone.pushed()?.serial ?? null,
              listeners,
              delegation: view,
              domains,
            };
          },
        }
      : {}),
    publish: (records) => rotate.publish(records),
    switchMode: (name, mode) => rotate.switchMode(name, mode),
    tracking: (domain) => tracking.view(domain),
    filter: hooks.filter,
    hasCheckHooks: hooks.hasCheckHooks,
  });
  const feedback = feedbackMethods({
    db,
    writer,
    log,
    signer,
    delivery,
    currentKey,
    scale,
    sharedBounces: () => config.sharedBounces,
  });
  await feedback.recover();
  const routes = routeMethods({
    db,
    writer,
    log,
    signer,
    delivery,
    currentKey,
    allowHttp: config.allowPrivateDestinations,
    storage: () => storage.state(),
    scale,
  });
  await routes.recover();
  const rotate = rotation({
    db,
    writer,
    log,
    signer,
    delivery,
    dns,
    sourceIp: config.sourceIps.map((x) => x.ip),
    inboundHost: config.inboundHostname,
    nsZone: config.ns?.zone ?? null,
    zoneServes,
    rotateDays: () => config.dkimRotateDays,
  });
  const tracking = trackingMethods({
    db,
    writer,
    log,
    signer,
    delivery,
    dns,
    publicUrl: config.publicUrl,
  });
  const linkTick = () => (links.coreRenewalDue() ? links.renewCore() : links.reconcileAll());
  void linkTick();
  const stopLinks = every(3_600_000, linkTick);
  const stopFleet = every(fleet.checkMs, () => fleet.check());
  const doctor = doctorMethods({
    db,
    config,
    delivery,
    rotation: rotate,
    paths: () => shaper.views(),
    storage: () => storage.state(),
    nodeCa: () => identity.current().ca,
    corePin: () => identity.current().pin,
    fleet: () => ({ health: fleet.health(), conflicts: fleet.conflicts() }),
  });
  const all = {
    ...api.methods,
    ...nodeMethods({ db, writer, log, signer, identity, links, health: () => fleet.health() }),
    ...feedback.methods,
    ...routes.methods,
    ...templateMethods({ db, writer }),
    ...projectMethods({ db, writer, log, ips: config.sourceIps }),
    ...tracking.methods,
    ...hooks.methods,
    ...doctor,
  };
  const admin = await serveRpc(adminSocket(config.runDir), all, { mode: "600" });
  const inboundDir = sock.coreInbound.slice(0, sock.coreInbound.lastIndexOf("/"));
  const made = await Bun.file(inboundDir)
    .stat()
    .then(() => true)
    .catch(() => false);
  if (!made) await privateDir(inboundDir, "750");
  const inbound = await serveRpc(sock.coreInbound, inboundMethods(all));
  const server = await serveRpc(sock.core, apiMethods(all));

  const shred = async () => {
    const ids = await writer.run((d) =>
      shredBodies(d, Date.now(), config.retentionDays * 24 * HOUR),
    );
    if (ids.length > 0) log.info("shredded bodies past retention", { count: ids.length });
  };
  const stopShred = every(Math.max(1_000, scaled(HOUR)), shred);
  const stopPrune = every(Math.max(1_000, scaled(HOUR)), () =>
    writer.run((d) => {
      pruneIdempotency(d, Date.now());
      pruneDmarc(d, Date.now());
      pruneConversations(d, Date.now() - config.retentionDays * 24 * HOUR);
      pruneRouted(d, Date.now() - config.retentionDays * 24 * HOUR);
      pruneUsage(d, Date.now());
      pruneRecipients(d, Date.now());
    }),
  );
  const seedRecipients = async () => {
    if (recipientsSeeded(db)) return;
    let after = 0;
    for (;;) {
      const page = seedPage(db, after, Date.now());
      const rows = await Promise.all(
        page.rows.map(async (r) => ({ ...r, hash: await recipientHash(r.address) })),
      );
      await writer.run((d) => {
        for (const r of rows) rememberRecipients(d, r.project, [r.hash], r.at);
        if (page.next === null) finishSeed(d, Date.now());
      });
      if (page.next === null) return;
      after = page.next;
    }
  };
  const runSeed = () => {
    seedRecipients().catch((err: Error) => {
      log.warn("could not fill the known recipients yet", { error: err.message });
      setTimeout(runSeed, scaled(60_000));
    });
  };
  runSeed();
  const purge = async () => {
    for (let i = 0; i < 20; i++) {
      const r = await writer.run((d) => purgeDeletedProject(d));
      if (r.finished) log.info("removed project purged", { project: r.project });
      if (r.messages === 0) return;
    }
  };
  const stopPurge = every(Math.max(1_000, scaled(10_000)), () =>
    purge().catch((err: Error) => log.error("project purge failed", { error: err.message })),
  );
  const stopTlsReports = every(Math.max(1_000, scaled(HOUR)), () =>
    sendTlsReports({
      db,
      writer,
      log,
      delivery,
      org: config.tlsrpt.org,
      contact: config.tlsrpt.contact,
      from: config.tlsrpt.from,
      enqueue: api.enqueueInternal,
    }).catch((err: Error) => log.warn("TLS reports failed", { error: err.message })),
  );
  const stopSuspensions = every(Math.max(1_000, scaled(MIN)), () =>
    writer.run((d) => expireSuspensions(d, Date.now())),
  );
  const stopVerify = every(Math.max(1_000, scaled(5 * MIN)), async () => {
    await api.verifyPending();
    await tracking.refresh();
  });
  const stopGuards = every(Math.max(1_000, scaled(MIN)), () =>
    writer
      .run((d) => {
        rollover(d, Date.now(), log);
        reputationGuard(d, Date.now(), config.guardMinVolume, log);
      })
      .catch((err: Error) => log.error("guard check failed", { error: err.message })),
  );
  const dayStats = b.object({
    day: b.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    spamRatio: b.number().nullable(),
    reputation: b.string().max(32).nullable(),
    spfRatio: b.number().nullable(),
    dkimRatio: b.number().nullable(),
    dmarcRatio: b.number().nullable(),
    encryptedRatio: b.number().nullable(),
  });
  const postmasterAnswer = b.object({
    enabled: b.boolean(),
    results: b.array(
      b.object({
        domain: b.string(),
        ok: b.boolean(),
        days: b.array(dayStats).max(400).optional(),
        error: b.string().max(2000).optional(),
      }),
    ),
  });
  const readPostmaster = async () => {
    const domains = allDomains(db)
      .filter((d) => d.status === "verified")
      .map((d) => d.name);
    if (domains.length === 0) return;
    const r = await dns
      .call("postmaster", { domains }, { result: postmasterAnswer, timeoutMs: 120_000 })
      .catch(() => null);
    if (!r?.enabled) return;
    for (const x of r.results) {
      if (!x.ok) log.warn("could not read Postmaster Tools", { domain: x.domain, error: x.error });
    }
    await writer.run((d) => {
      const at = Date.now();
      for (const x of r.results) if (x.ok && x.days) savePostmaster(d, x.domain, x.days, at);
      gmailGuard(d, domains, at, log);
    });
  };
  const stopPostmaster = every(Math.max(1_000, scaled(6 * HOUR)), () =>
    readPostmaster().catch((err: Error) =>
      log.error("Postmaster Tools check failed", { error: err.message }),
    ),
  );
  setTimeout(() => void readPostmaster().catch(() => {}), Math.max(1_000, scaled(2 * MIN)));
  const stopRotation = every(Math.max(1_000, scaled(HOUR)), () => rotate.tick());
  const stopStorage = every(30_000, () => storage.check());
  const stopListed = config.sourceIps.length
    ? every(Math.max(1_000, scaled(10 * MIN)), refreshListed)
    : () => {};
  if (config.sourceIps.length) setTimeout(() => void refreshListed(), Math.max(1_000, scaled(MIN)));
  const stopProject = every(250, () =>
    feedback
      .project()
      .catch((err: Error) => log.error("webhook projection failed", { error: err.message })),
  );
  const stopDispatch = every(250, () =>
    feedback
      .dispatch()
      .catch((err: Error) => log.error("webhook dispatch failed", { error: err.message })),
  );
  const stopResend = every(1_000, () =>
    feedback
      .resend()
      .catch((err: Error) => log.error("webhook resend failed", { error: err.message })),
  );
  const stopRoutes = every(250, () =>
    routes
      .dispatch()
      .catch((err: Error) => log.error("route dispatch failed", { error: err.message })),
  );

  const stopEventLog = eventLog
    ? every(1_000, () =>
        exportEvents((fn) => writer.run(fn), eventLog, Date.now).catch((err: Error) =>
          log.warn("event log write failed", { error: err.message }),
        ),
      )
    : () => {};

  const stopSettled = every(5_000, flushSettled);

  const stopZone = zone ? every(10_000, () => zone.tick()) : () => {};
  if (zone) setTimeout(() => void zone.tick(), 1_000);
  const stopProbe = probe ? every(10_000, () => probe.poll()) : () => {};
  if (probe) setTimeout(() => void probe.poll(), 3_000);
  const stopDelegation = delegation
    ? every(Math.max(1_000, scaled(HOUR)), () => delegation.poll())
    : () => {};
  if (delegation) setTimeout(() => void delegation.poll(), 30_000);

  const tel = config.otlp
    ? telemetry({
        delivery,
        log,
        instance: config.ehloName ?? "bunzzle",
        metricsIntervalMs: config.otlp.metricsIntervalMs,
        families: api.families,
        startedAt: Date.now(),
      })
    : null;
  if (tel) spanSink = (s) => tel.record(s);

  await scheduler.start();
  onStop(log, async () => {
    await tel?.stop();
    stopLinks();
    stopFleet();
    links.closeAll();
    stopSettled();
    stopZone();
    stopProbe();
    stopDelegation();
    stopShred();
    stopPrune();
    stopPurge();
    stopSuspensions();
    stopTlsReports();
    stopVerify();
    stopProject();
    stopGuards();
    stopRotation();
    stopStorage();
    stopPostmaster();
    stopListed();
    stopDispatch();
    stopResend();
    stopRoutes();
    stopEventLog();
    await eventLog?.stop();
    server.stop();
    inbound.stop();
    admin.stop();
    shaper.stop();
    await scheduler.stop();
    writer.close();
    db.close();
  });
  log.info("core ready", { db: config.dbPath });
  ready();
}
