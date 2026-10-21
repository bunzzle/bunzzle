import { enqueue } from "../src/core/jobs.ts";
import { createLogger } from "../src/core/log.ts";
import { ok } from "../src/core/outcome.ts";
import { openDatabase } from "../src/core/store/db.ts";
import { Writer } from "../src/core/store/writer.ts";
import { Scheduler } from "../src/scheduler/scheduler.ts";

const blast = Number(Bun.argv[2] ?? 50_000);
const singles = Number(Bun.argv[3] ?? 100);
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-bench-${crypto.randomUUID()}`;
await Bun.$`mkdir -p ${dir}`.quiet();

const db = openDatabase({ path: `${dir}/bunzzle.db` });
db.run("INSERT INTO projects (id, name, created_at) VALUES ('small', 'small', 0)");
const writer = new Writer(db);
const payload = { to: ["someone@example.com"] };

await writer.run((d) => {
  for (let i = 0; i < blast; i++)
    enqueue(d, { project: "default", type: "email", payload }, Date.now());
});

const queuedAt = new Map<string, number>();
const latency: number[] = [];
let done = 0;
const scheduler = new Scheduler({
  db,
  writer,
  handle: async (job) => {
    await Bun.sleep(5);
    const t = queuedAt.get(job.messageId);
    if (t !== undefined) latency.push(performance.now() - t);
    done++;
    return ok.done;
  },
  log: createLogger("error"),
  concurrency: 64,
});
const start = performance.now();
await scheduler.start();
for (let i = 0; i < singles; i++) {
  await Bun.sleep(10);
  const t = performance.now();
  const id = await writer.run((d) =>
    enqueue(d, { project: "small", type: "email", payload }, Date.now()),
  );
  queuedAt.set(id, t);
}
while (latency.length < singles) await Bun.sleep(10);
const smallDone = (performance.now() - start) / 1000;
while (done < blast + singles) await Bun.sleep(10);
const allDone = (performance.now() - start) / 1000;
await scheduler.stop();
writer.close();
db.close();
await Bun.$`rm -rf ${dir}`.quiet();

latency.sort((a, b) => a - b);
const pct = (p: number) => (latency[Math.floor((latency.length - 1) * p)] ?? 0).toFixed(0);
console.log(
  `fair queue benchmark: ${blast} queued by one project, ${singles} single emails from another, 64 slots, 5 ms per send`,
);
console.log(
  `single emails: p50 ${pct(0.5)} ms, p99 ${pct(0.99)} ms, all sent after ${smallDone.toFixed(1)} s`,
);
console.log(`everything sent after ${allDone.toFixed(1)} s`);
