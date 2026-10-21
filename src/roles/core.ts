import { purgeDeletedProject } from "../accounts/purge.ts";
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
import { shredBodies } from "../delivery/queue.ts";
import type { DeliveryTransport } from "../delivery/transport.ts";
import { pruneDmarc } from "../dmarc/store.ts";
import { allDomains, bounceDomain, findDomain, returnPathReady } from "../domains/domains.ts";
import { pruneIdempotency } from "../emails/idempotency.ts";
import { pruneConversations } from "../emails/view.ts";
import { beginAtEnd, exportEvents } from "../eventlog/export.ts";
import { EventLog } from "../eventlog/log.ts";
import { gmailGuard, savePostmaster } from "../guards/gmail.ts";
import { reputationGuard } from "../guards/guards.ts";
import { pruneRouted } from "../inbound/routes.ts";
import { RpcClient, serveRpc } from "../ipc/rpc.ts";
import { rollover } from "../ips/warmup.ts";
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
import { projectMethods } from "./core-projects.ts";
import { rotation } from "./core-rotation.ts";
import { routeMethods } from "./core-routes.ts";
import { templateMethods } from "./core-templates.ts";
import { trackingMethods } from "./core-tracking.ts";
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
const MAX_SETTLED = 50_000;

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

  let settled: string[] = [];
  const takeSettled = () => settled.splice(0, 5000);
  const transport: DeliveryTransport = {
    lookup: (domain) =>
      delivery.call("lookup", { domain }, { result: destinationWire, timeoutMs: 2 * MIN }),
    deliver: (req) => {
      const keys = takeSettled();
      return delivery
        .call("deliver", requestToWire({ ...req, ...(keys.length ? { settled: keys } : {}) }), {
          result: deliveryReportWire,
          timeoutMs: 40 * MIN,
        })
        .catch((err) => {
          settled = keys.concat(settled);
          throw err;
        });
    },
    forget: (keys) => {
      settled.push(...keys);
      if (settled.length > MAX_SETTLED) settled.splice(0, settled.length - MAX_SETTLED);
    },
  };
  const flushSettled = async () => {
    const keys = takeSettled();
    if (keys.length === 0) return;
    try {
      await delivery.call("forget", { keys }, { timeoutMs: 10_000 });
    } catch {
      settled = keys.concat(settled);
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
    maxWaitMs: Math.max(1_000, Math.floor(Math.max(2_000, scaled(45 * MIN)) / 3)),
    bounceDomainFor: (d) => (returnPathReady(findDomain(db, d)) ? bounceDomain(d) : null),
    relayRoutes: () =>
      config.relay && !config.relay.for.all
        ? { targets: config.relay.for.targets, blocked: config.relay.for.blocked }
        : null,
    listed: (ip) => listed.has(ip),
  });
  const scheduler = new Scheduler({
    db,
    writer,
    log,
    handle: (job): Promise<Outcome> =>
      job.type === "email"
        ? handleEmail(job)
        : Promise.resolve(fail("unknown-type", `no handler for ${job.type}`)),
    retry: scaledPolicy(defaultRetryPolicy, scale),
    reconcileMs: scaled(15 * MIN),
    leaseMs: Math.max(2_000, scaled(45 * MIN)),
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

  const hooks = hookMethods({ db, writer, log, delivery });
  const api = coreMethods({
    db,
    writer,
    log,
    signer,
    delivery,
    currentKey,
    sourceIp: config.sourceIps.map((x) => x.ip),
    inboundHost: config.inboundHostname,
    anomalyFloor: () => config.anomalyFloor,
    ips: config.sourceIps,
    paths: () => shaper.views(),
    storage: () => storage.state(),
    publish: (records) => rotate.publish(records),
    tracking: (domain) => tracking.view(domain),
    scan: hooks.scan,
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
  const doctor = doctorMethods({
    db,
    config,
    delivery,
    rotation: rotate,
    paths: () => shaper.views(),
    storage: () => storage.state(),
  });
  const all = {
    ...api.methods,
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
    }),
  );
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

  await scheduler.start();
  onStop(log, async () => {
    stopSettled();
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
