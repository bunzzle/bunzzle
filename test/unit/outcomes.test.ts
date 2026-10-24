import type { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import { type ClaimedJob, claim, holdsLease, settle } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import type { Outcome } from "../../src/core/outcome.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail, pendingRecipients } from "../../src/delivery/queue.ts";
import type { DeliverRequest, DeliveryTransport } from "../../src/delivery/transport.ts";
import { RpcError } from "../../src/ipc/rpc.ts";
import type { JobContext } from "../../src/scheduler/scheduler.ts";
import { Shaper } from "../../src/shaping/shaper.ts";
import type { DeliveryReport } from "../../src/smtp/deliver.ts";
import type { OnOutcomes, RecipientResult } from "../../src/smtp/session.ts";

type Deliver = (req: DeliverRequest, onOutcomes?: OnOutcomes) => Promise<DeliveryReport>;

const dot = (address: string, code = 250): RecipientResult => ({
  address,
  status: code === 250 ? "delivered" : code < 500 ? "deferred" : "bounced",
  phase: "dot",
  code,
  enhanced: code === 250 ? "2.0.0" : code < 500 ? "4.3.0" : "5.6.0",
  reply: `${code} queued`,
});

const rcpt = (address: string): RecipientResult => ({
  address,
  status: "bounced",
  phase: "rcpt",
  code: 550,
  enhanced: "5.1.1",
  reply: "550 5.1.1 no such user",
});

function setup(deliver: Deliver) {
  const clock = manualClock();
  const db = openDatabase({ path: ":memory:" });
  const log = createLogger("error", {}, () => {});
  const transport: DeliveryTransport = {
    lookup: async (domain) => ({
      kind: "targets",
      domain,
      mxHosts: ["mx.example.test"],
      implicit: false,
      authenticated: false,
      targets: [{ host: "mx.example.test", preference: 10, address: "192.0.2.1", family: 4 }],
      skipped: [],
    }),
    deliver,
  };
  const handle = deliveryHandler({ db, log, transport, clock, shaper: new Shaper({ log, clock }) });
  enqueueEmail(
    db,
    DEFAULT_PROJECT,
    {
      id: "m",
      body: { epoch: 1, wrapped: new Uint8Array(1), body: new Uint8Array(1) },
      from: "a@bunzzle.test",
      recipients: ["x@example.test", "y@example.test", "z@example.test"],
      smtpUtf8: false,
      requireTls: false,
    },
    clock.now(),
  );
  const take = () => {
    const [job] = claim(db, clock.now(), 1, 60_000);
    if (!job) throw new Error("nothing claimed");
    return job;
  };
  const ctx = (job: ClaimedJob): JobContext => ({
    renew: async () => true,
    record: async (write) => {
      if (!holdsLease(db, job)) return false;
      write(db, clock.now());
      return true;
    },
  });
  const run = async (job: ClaimedJob, context = ctx(job)) => {
    let outcome: Outcome;
    try {
      outcome = await handle(job, undefined, context);
    } catch (err) {
      outcome = { kind: "unknown", reason: (err as Error).message };
    }
    const settled = settle(db, job, outcome, clock.now(), {
      retry: defaultRetryPolicy,
      reconcileMs: 60_000,
    });
    return { outcome, settled };
  };
  return { db, clock, take, ctx, run };
}

const status = (db: Database) =>
  Object.fromEntries(
    db
      .query<{ address: string; status: string; attempts: number }, []>(
        "SELECT address, status, attempts FROM recipients ORDER BY address",
      )
      .all()
      .map((r) => [r.address.slice(0, 1), `${r.status}/${r.attempts}`]),
  );

const recipientEvents = (db: Database) =>
  db
    .query<{ data: string }, []>("SELECT data FROM events WHERE kind = 'recipient' ORDER BY id")
    .all()
    .map((e) => (JSON.parse(e.data) as { address: string }).address.slice(0, 1));

describe("attempt outcomes as they happen", () => {
  test("link cut mid-batch: reported outcomes stay, the rest stay pending", async () => {
    const s = setup(async (_req, onOutcomes) => {
      onOutcomes?.([dot("x@example.test"), dot("y@example.test")]);
      throw new RpcError("lost", "connection to node-a lost");
    });
    const job = s.take();
    const { settled } = await s.run(job);
    expect(settled).toBe("unknown");
    expect(status(s.db)).toEqual({ x: "delivered/1", y: "delivered/1", z: "queued/0" });
    expect(pendingRecipients(s.db, job.id)).toEqual(["z@example.test"]);
    expect(recipientEvents(s.db)).toEqual(["x", "y"]);
  });

  test("node killed after every outcome was reported: the job is done, not unknown", async () => {
    const s = setup(async (req, onOutcomes) => {
      onOutcomes?.(req.recipients.map((a) => dot(a)));
      throw new RpcError("lost", "connection to node-a lost");
    });
    const { outcome, settled } = await s.run(s.take());
    expect(outcome.kind).toBe("done");
    expect(settled).toBe("done");
    expect(status(s.db)).toEqual({ x: "delivered/1", y: "delivered/1", z: "delivered/1" });
    expect(recipientEvents(s.db)).toEqual(["x", "y", "z"]);
  });

  test("outcomes reported twice and again in the report are recorded once", async () => {
    const s = setup(async (req, onOutcomes) => {
      onOutcomes?.([dot("x@example.test"), dot("y@example.test")]);
      onOutcomes?.([dot("x@example.test"), dot("y@example.test")]);
      return {
        domain: req.domain,
        destination: req.destination,
        provider: null,
        policy: null,
        sessions: [],
        recipients: [dot("x@example.test"), dot("y@example.test"), rcpt("z@example.test")],
      };
    });
    const { settled } = await s.run(s.take());
    expect(settled).toBe("done");
    expect(status(s.db)).toEqual({ x: "delivered/1", y: "delivered/1", z: "bounced/1" });
    expect(recipientEvents(s.db)).toEqual(["x", "y", "z"]);
  });

  test("a recalled report does not rewrite recipients already recorded", async () => {
    let calls = 0;
    const s = setup(async (req, onOutcomes) => {
      calls++;
      if (calls === 1) {
        onOutcomes?.([dot("x@example.test"), dot("y@example.test")]);
        throw new RpcError("timeout", "deliver timed out");
      }
      expect(req.recipients).toEqual(["z@example.test"]);
      return {
        domain: req.domain,
        destination: req.destination,
        provider: null,
        policy: null,
        sessions: [],
        recipients: [dot("x@example.test"), dot("y@example.test"), dot("z@example.test", 451)],
        recalled: true,
      };
    });
    await s.run(s.take());
    s.clock.advance(61_000);
    s.db
      .query("UPDATE jobs SET state = 'ready', run_after = 0, unresolved_attempt = attempt")
      .run();
    const { settled } = await s.run(s.take());
    expect(settled).toBe("retry");
    expect(status(s.db)).toEqual({ x: "delivered/1", y: "delivered/1", z: "deferred/1" });
    expect(recipientEvents(s.db)).toEqual(["x", "y", "z"]);
  });

  test("outcomes not recorded early because the lease was lost come with the report", async () => {
    const s = setup(async (req, onOutcomes) => {
      onOutcomes?.([dot("x@example.test")]);
      return {
        domain: req.domain,
        destination: req.destination,
        provider: null,
        policy: null,
        sessions: [],
        recipients: req.recipients.map((a) => dot(a)),
      };
    });
    const job = s.take();
    const outcome = await s.run(job, { renew: async () => true, record: async () => false });
    expect(outcome.settled).toBe("done");
    expect(status(s.db)).toEqual({ x: "delivered/1", y: "delivered/1", z: "delivered/1" });
    expect(recipientEvents(s.db)).toEqual(["x", "y", "z"]);
  });

  test("without a recorder the batch report records everything", async () => {
    const s = setup(async (req, onOutcomes) => {
      expect(onOutcomes).toBeUndefined();
      return {
        domain: req.domain,
        destination: req.destination,
        provider: null,
        policy: null,
        sessions: [],
        recipients: req.recipients.map((a) => dot(a)),
      };
    });
    await s.run(s.take(), { renew: async () => true });
    expect(status(s.db)).toEqual({ x: "delivered/1", y: "delivered/1", z: "delivered/1" });
  });
});
