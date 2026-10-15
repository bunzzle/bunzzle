import { z } from "zod";
import type { Config } from "../config.ts";
import { countByState } from "../core/jobs.ts";
import type { Logger } from "../core/log.ts";
import { fail, type Outcome } from "../core/outcome.ts";
import { defaultRetryPolicy, type RetryPolicy } from "../core/retry.ts";
import { openDatabase } from "../core/store/db.ts";
import { Writer } from "../core/store/writer.ts";
import { type EpochPublicKey, epochOf, sealBody } from "../crypto/envelope.ts";
import { deliveryHandler } from "../delivery/handler.ts";
import { emailExists, enqueueEmail, recipientsOf, shredBodies } from "../delivery/queue.ts";
import type { DeliveryTransport } from "../delivery/transport.ts";
import { method, RpcClient, RpcError, serveRpc } from "../ipc/rpc.ts";
import { domainOf, normalizeAddress } from "../mime/address.ts";
import { senderDomainOf } from "../mime/from.ts";
import { Scheduler } from "../scheduler/scheduler.ts";
import { every, onStop, privateDir, ready } from "./runtime.ts";
import {
  deliveryReportWire,
  destinationWire,
  enqueueParams,
  epochKeyFromWire,
  epochKeyWire,
  MESSAGE_ID,
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
  const handleEmail = deliveryHandler({
    db,
    log,
    transport,
    source: config.sourceIp ?? "default",
    pauseMs: scaled(HOUR),
    maxPauseMs: scaled(12 * HOUR),
    slowMs: scaled(10 * MIN),
    busyRetryMs: scaled(MIN),
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

  const server = await serveRpc(sock.core, {
    enqueue: method(enqueueParams, async (p) => {
      const id = p.id ?? Bun.randomUUIDv7();
      if (emailExists(db, id)) return { id, existed: true };
      const domains = await signer.call("domains", {}, { result: z.array(z.string()) });
      let headerDomain: string;
      let envelopeFrom: string;
      try {
        headerDomain = senderDomainOf(p.data);
        envelopeFrom = normalizeAddress(p.from);
      } catch (err) {
        throw new RpcError("invalid", (err as Error).message);
      }
      if (!domains.includes(headerDomain)) {
        throw new RpcError("invalid", `no DKIM key for ${headerDomain}; it cannot send`);
      }
      if (domainOf(envelopeFrom) !== headerDomain) {
        throw new RpcError("invalid", "the envelope sender must use the From header's domain");
      }
      const body = await sealBody(await currentKey(), id, p.data);
      try {
        await writer.run((d) =>
          enqueueEmail(
            d,
            {
              id,
              body,
              from: envelopeFrom,
              recipients: p.recipients,
              smtpUtf8: p.smtpUtf8,
              requireTls: p.requireTls,
              ...(p.expiresAt !== undefined ? { expiresAt: p.expiresAt } : {}),
              ...(p.priority !== undefined ? { priority: p.priority } : {}),
            },
            Date.now(),
          ),
        );
      } catch (err) {
        if (emailExists(db, id)) return { id, existed: true };
        throw new RpcError("invalid", (err as Error).message);
      }
      return { id, existed: false };
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
    health: method(z.object({}), () => ({ ok: true, jobs: countByState(db) })),
  });

  const shred = async () => {
    const ids = await writer.run((d) =>
      shredBodies(d, Date.now(), config.retentionDays * 24 * HOUR),
    );
    if (ids.length > 0) log.info("shredded bodies past retention", { count: ids.length });
  };
  const stopShred = every(Math.max(1_000, scaled(HOUR)), shred);

  await scheduler.start();
  onStop(log, async () => {
    stopShred();
    server.stop();
    await scheduler.stop();
    writer.close();
    db.close();
  });
  log.info("core ready", { db: config.dbPath });
  ready();
}
