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
import { bounceDomain, getDomain, returnPathReady } from "../domains/domains.ts";
import { pruneIdempotency } from "../emails/idempotency.ts";
import { pruneConversations } from "../emails/view.ts";
import { beginAtEnd, exportEvents } from "../eventlog/export.ts";
import { EventLog } from "../eventlog/log.ts";
import { reputationGuard } from "../guards/guards.ts";
import { RpcClient, serveRpc } from "../ipc/rpc.ts";
import { rollover } from "../ips/warmup.ts";
import { expireSuspensions } from "../queue/control.ts";
import { Scheduler } from "../scheduler/scheduler.ts";
import { type ControlState, DEFAULT_TUNING } from "../shaping/control.ts";
import { Shaper } from "../shaping/shaper.ts";
import { sendTlsReports } from "../tlsrpt/job.ts";
import { coreMethods } from "./core-api.ts";
import { doctorMethods, ipInfo } from "./core-doctor.ts";
import { feedbackMethods } from "./core-feedback.ts";
import { rotation } from "./core-rotation.ts";
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
  const storage = new StorageWatch(config.dataDir, config.minFreeMb, log);
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
    bounceDomainFor: (d) => (returnPathReady(getDomain(db, d)) ? bounceDomain(d) : null),
    relayRoutes:
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

  const api = coreMethods({
    db,
    writer,
    log,
    signer,
    delivery,
    currentKey,
    sourceIp: config.sourceIps.map((x) => x.ip),
    inboundHost: config.inboundHostname,
    anomalyFloor: config.anomalyFloor,
    ips: config.sourceIps,
    paths: () => shaper.views(),
    storage: () => storage.state(),
    publish: (records) => rotate.publish(records),
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
  const rotate = rotation({
    db,
    writer,
    log,
    signer,
    delivery,
    dns,
    sourceIp: config.sourceIps.map((x) => x.ip),
    inboundHost: config.inboundHostname,
    rotateDays: config.dkimRotateDays,
  });
  const doctor = doctorMethods({
    db,
    config,
    delivery,
    rotation: rotate,
    paths: () => shaper.views(),
    storage: () => storage.state(),
  });
  const server = await serveRpc(sock.core, {
    ...api.methods,
    ...feedback.methods,
    ...doctor,
  });

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
    }),
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
  const stopVerify = every(Math.max(1_000, scaled(5 * MIN)), () => api.verifyPending());
  const stopGuards = every(Math.max(1_000, scaled(MIN)), () =>
    writer
      .run((d) => {
        rollover(d, Date.now(), log);
        reputationGuard(d, Date.now(), config.guardMinVolume, log);
      })
      .catch((err: Error) => log.error("guard check failed", { error: err.message })),
  );
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
    stopSuspensions();
    stopTlsReports();
    stopVerify();
    stopProject();
    stopGuards();
    stopRotation();
    stopStorage();
    stopListed();
    stopDispatch();
    stopEventLog();
    await eventLog?.stop();
    server.stop();
    shaper.stop();
    await scheduler.stop();
    writer.close();
    db.close();
  });
  log.info("core ready", { db: config.dbPath });
  ready();
}
