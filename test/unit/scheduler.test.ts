import { describe, expect, test } from "bun:test";
import { countByState, enqueue } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { defer, type Outcome, ok } from "../../src/core/outcome.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { type JobHandler, Scheduler } from "../../src/scheduler/scheduler.ts";

const quietLog = createLogger("error", {}, () => {});
const fastRetry = {
  stepsMs: [1, 2],
  everyMs: 5,
  jitter: 0,
  maxAttempts: 5,
  maxAgeMs: 60_000,
  noticesMs: [],
};

function setup(handle: JobHandler, extra: { concurrency?: number; leaseMs?: number } = {}) {
  const db = openDatabase({ path: ":memory:" });
  const writer = new Writer(db);
  const scheduler = new Scheduler({
    db,
    writer,
    handle,
    log: quietLog,
    retry: fastRetry,
    reconcileMs: 0,
    sweepMs: 20,
    ...extra,
  });
  const add = (n: number) =>
    Promise.all(
      Array.from({ length: n }, (_, i) =>
        writer.run((d) => enqueue(d, { project: "default", type: "t", payload: i }, Date.now())),
      ),
    );
  return { db, writer, scheduler, add };
}

async function until(cond: () => boolean, ms = 5_000) {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timed out");
    await Bun.sleep(5);
  }
}

describe("Scheduler", () => {
  test("runs every job to done", async () => {
    const { db, scheduler, add } = setup(async () => ok.done);
    await scheduler.start();
    await add(500);
    await until(() => countByState(db).done === 500);
    await scheduler.stop();
    expect(scheduler.stats).toMatchObject({ claimed: 500, done: 500, stale: 0 });
  });

  test("never exceeds its concurrency", async () => {
    let active = 0;
    let peak = 0;
    const { db, scheduler, add } = setup(
      async () => {
        peak = Math.max(peak, ++active);
        await Bun.sleep(2);
        active--;
        return ok.done;
      },
      { concurrency: 4 },
    );
    await add(40);
    await scheduler.start();
    await until(() => countByState(db).done === 40);
    await scheduler.stop();
    expect(peak).toBe(4);
  });

  test("retries deferred jobs until they succeed", async () => {
    const tries = new Map<unknown, number>();
    const { db, scheduler, add } = setup(async (job): Promise<Outcome> => {
      const n = (tries.get(job.payload) ?? 0) + 1;
      tries.set(job.payload, n);
      return n < 3 ? defer("busy") : ok.done;
    });
    await add(20);
    await scheduler.start();
    await until(() => countByState(db).done === 20);
    await scheduler.stop();
    expect([...tries.values()].every((n) => n === 3)).toBe(true);
  });

  test("a throwing handler leads to unknown, then a resend", async () => {
    let calls = 0;
    const { db, scheduler, add } = setup(async () => {
      if (++calls === 1) throw new Error("connection reset");
      return ok.done;
    });
    await add(1);
    await scheduler.start();
    await until(() => countByState(db).done === 1);
    await scheduler.stop();
    const kinds = db
      .query<{ kind: string }, []>("SELECT kind FROM events ORDER BY id")
      .all()
      .map((r) => r.kind);
    expect(kinds).toEqual(["queued", "unknown", "duplicate_risk", "done"]);
  });

  test("a handler past its lease is aborted and the job is reconciled", async () => {
    let calls = 0;
    const { db, scheduler, add } = setup(
      (_job, signal) =>
        new Promise<Outcome>((resolve) => {
          if (++calls > 1) return resolve(ok.done);
          signal.addEventListener("abort", () => resolve({ kind: "unknown", reason: "aborted" }));
        }),
      { leaseMs: 50 },
    );
    await add(1);
    await scheduler.start();
    await until(() => countByState(db).done === 1);
    await scheduler.stop();
    expect(calls).toBe(2);
  });

  test("stop waits for jobs in flight", async () => {
    let finished = false;
    const { db, scheduler, add } = setup(async () => {
      await Bun.sleep(30);
      finished = true;
      return ok.done;
    });
    await add(1);
    await scheduler.start();
    await until(() => scheduler.inFlight === 1);
    await scheduler.stop();
    expect(finished).toBe(true);
    expect(countByState(db).done).toBe(1);
  });
});
