import { countByState, enqueue } from "../src/core/jobs.ts";
import { createLogger } from "../src/core/log.ts";
import { ok } from "../src/core/outcome.ts";
import { openDatabase } from "../src/core/store/db.ts";
import { Writer } from "../src/core/store/writer.ts";
import { Scheduler } from "../src/scheduler/scheduler.ts";

const total = Number(Bun.argv[2] ?? 100_000);
const concurrent = Number(Bun.argv[3] ?? 1_000);
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-bench-${crypto.randomUUID()}`;
await Bun.$`mkdir -p ${dir}`.quiet();

const db = openDatabase({ path: `${dir}/bunzzle.db` });
const writer = new Writer(db);
let commits = 0;
writer.onCommit(() => commits++);

const payload = {
  from: "Acme <hello@acme.dev>",
  to: ["someone@example.com"],
  subject: "Your sign-in link",
  html: `<p>${"x".repeat(1_500)}</p>`,
};

const latencies: number[] = [];
const intakeStart = performance.now();
let next = 0;
async function client() {
  while (next < total) {
    next++;
    const t = performance.now();
    await writer.run((d) => enqueue(d, { type: "email", payload }, Date.now()));
    latencies.push(performance.now() - t);
  }
}
await Promise.all(Array.from({ length: concurrent }, client));
const intakeSec = (performance.now() - intakeStart) / 1000;
latencies.sort((a, b) => a - b);
const pct = (p: number) => (latencies[Math.floor((latencies.length - 1) * p)] ?? 0).toFixed(2);

const intakeCommits = commits;
const scheduler = new Scheduler({
  db,
  writer,
  handle: async () => ok.done,
  log: createLogger("error"),
  concurrency: 512,
});
const runStart = performance.now();
await scheduler.start();
while (countByState(db).done < total) await Bun.sleep(10);
const runSec = (performance.now() - runStart) / 1000;
await scheduler.stop();
writer.close();
db.close();
await Bun.$`rm -rf ${dir}`.quiet();

console.log(
  `queue benchmark: ${total} messages, ${concurrent} concurrent producers, synchronous=FULL`,
);
console.log(
  `intake:        ${Math.round(total / intakeSec)} msg/s  (p50 ${pct(0.5)} ms, p99 ${pct(0.99)} ms, ${intakeCommits} commits, ${Math.round(total / intakeCommits)} per commit)`,
);
console.log(`claim+settle:  ${Math.round(total / runSec)} msg/s  (no-op handler, concurrency 512)`);
