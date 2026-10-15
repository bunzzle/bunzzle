import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { fail, type Outcome } from "../core/outcome.ts";
import { defaultRetryPolicy, type RetryPolicy } from "../core/retry.ts";
import { openDatabase } from "../core/store/db.ts";
import { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, epochOf } from "../crypto/envelope.ts";
import { deliveryHandler } from "../delivery/handler.ts";
import { shredBodies } from "../delivery/queue.ts";
import type { DeliveryTransport } from "../delivery/transport.ts";
import { pruneIdempotency } from "../emails/idempotency.ts";
import { RpcClient, serveRpc } from "../ipc/rpc.ts";
import { Scheduler } from "../scheduler/scheduler.ts";
import { type ControlState, DEFAULT_TUNING } from "../shaping/control.ts";
import { Shaper } from "../shaping/shaper.ts";
import { coreMethods } from "./core-api.ts";
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
  const sock = sockets(config.runDir);
  const signer = new RpcClient(sock.signer);
  const delivery = new RpcClient(sock.delivery);

  const transport: DeliveryTransport = {
    lookup: (domain) =>
      delivery.call("lookup", { domain }, { result: destinationWire, timeoutMs: 2 * MIN }),
    deliver: (req) =>
      delivery.call("deliver", requestToWire(req), {
        result: deliveryReportWire,
        timeoutMs: 40 * MIN,
      }),
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
  const handleEmail = deliveryHandler({
    db,
    log,
    transport,
    shaper,
    source: config.sourceIp ?? "default",
    busyRetryMs: scaled(MIN),
    maxWaitMs: Math.max(1_000, Math.floor(Math.max(2_000, scaled(45 * MIN)) / 3)),
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
    sourceIp: config.sourceIp,
    paths: () => shaper.views(),
  });
  const server = await serveRpc(sock.core, api.methods);

  const shred = async () => {
    const ids = await writer.run((d) =>
      shredBodies(d, Date.now(), config.retentionDays * 24 * HOUR),
    );
    if (ids.length > 0) log.info("shredded bodies past retention", { count: ids.length });
  };
  const stopShred = every(Math.max(1_000, scaled(HOUR)), shred);
  const stopPrune = every(Math.max(1_000, scaled(HOUR)), () =>
    writer.run((d) => pruneIdempotency(d, Date.now())),
  );
  const stopVerify = every(Math.max(1_000, scaled(5 * MIN)), () => api.verifyPending());

  await scheduler.start();
  onStop(log, async () => {
    stopShred();
    stopPrune();
    stopVerify();
    server.stop();
    shaper.stop();
    await scheduler.stop();
    writer.close();
    db.close();
  });
  log.info("core ready", { db: config.dbPath });
  ready();
}
