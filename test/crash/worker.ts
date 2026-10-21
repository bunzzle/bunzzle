import { enqueue, pendingCount } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { defer, ok, unknown } from "../../src/core/outcome.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { Scheduler } from "../../src/scheduler/scheduler.ts";

const dbPath = Bun.env["CRASH_DB"] as string;
const sink = Bun.env["CRASH_SINK"] as string;
const total = Number(Bun.env["CRASH_N"]);
const chunk = 1_000;

export const messageId = (i: number) => `m${String(i).padStart(7, "0")}`;

const db = openDatabase({ path: dbPath });
const writer = new Writer(db);
const scheduler = new Scheduler({
  db,
  writer,
  log: createLogger("error", { service: "crash-worker" }),
  concurrency: 128,
  leaseMs: 10_000,
  reconcileMs: 0,
  sweepMs: 50,
  retry: {
    stepsMs: [2, 10, 25],
    everyMs: 50,
    jitter: 1,
    maxAttempts: 100,
    maxAgeMs: 3_600_000,
    noticesMs: [],
  },
  handle: async (job, signal) => {
    let res: Response;
    try {
      res = await fetch(`${sink}/send`, { method: "POST", body: job.id, signal });
    } catch (err) {
      return unknown((err as Error).message);
    }
    if (res.status === 200) return ok.done;
    if (res.status === 503) return defer("sink busy");
    return unknown(`sink answered ${res.status}`);
  },
});

async function ack(ids: string[]) {
  for (let attempt = 1; ; attempt++) {
    try {
      await fetch(`${sink}/ack`, { method: "POST", body: JSON.stringify(ids) });
      return;
    } catch (err) {
      if (attempt === 5) throw err;
      await Bun.sleep(10 * attempt);
    }
  }
}

await scheduler.start();

const existing = new Set(
  db
    .query<{ id: string }, []>("SELECT id FROM messages")
    .all()
    .map((r) => r.id),
);
const missing: string[] = [];
for (let i = 0; i < total; i++) {
  const id = messageId(i);
  if (!existing.has(id)) missing.push(id);
}

for (let i = 0; i < missing.length; i += chunk) {
  const ids = missing.slice(i, i + chunk);
  await Promise.all(
    ids.map((id) =>
      writer.run((d) =>
        enqueue(d, { project: "default", id, type: "crash", payload: { id } }, Date.now()),
      ),
    ),
  );
  await ack(ids);
}

while (pendingCount(db) > 0) await Bun.sleep(50);
await scheduler.stop();
writer.close();
db.close();
process.exit(0);
