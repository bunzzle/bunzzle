import { Database } from "bun:sqlite";
import { cpuByRole, email, pct, startBench, usage } from "./setup.ts";
import { behaviorOf, startSink } from "./sink.ts";

const total = Number(Bun.argv[2] ?? 1_000_000);
const destinations = Number(Bun.argv[3] ?? 1_000);
const concurrency = Number(Bun.argv[4] ?? 8);
const backlog = Bun.argv[5] === "backlog";
const BACKLOG_MS = 8 * 60_000;
const BATCH = 100;
const SAMPLE_MS = 10_000;
const STALL_MS = 40 * 60_000;
const TAIL_MS = 2 * 60_000;

const sink = startSink(total);
const bench = await startBench(destinations, {
  sink,
  env: { BUNZZLE_ANOMALY_FLOOR: "100000000", BUNZZLE_PUBLIC_URL: "https://bench.test" },
});
const headers = { authorization: `Bearer ${bench.token}`, "content-type": "application/json" };

const mix = new Map<string, number>();
for (let d = 0; d < destinations; d++) {
  const b = behaviorOf(d);
  mix.set(b, (mix.get(b) ?? 0) + 1);
}
console.log(
  `scale benchmark: ${total} bulk emails to ${destinations} destinations (${[...mix].map(([b, n]) => `${n} ${b}`).join(", ")}), plus one transactional probe per second`,
);

const dbSize = async () =>
  Number((await Bun.$`du -sk ${bench.dir}/data`.nothrow().text()).split(/\s+/)[0] ?? 0) / 1024;

let accepted = 0;
let intakeErrors = 0;
let firstError: string | null = null;
let intakeDone = 0;
const started = performance.now();
const releaseAt = new Date(Date.now() + BACKLOG_MS).toISOString();
const intake = (async () => {
  let next = 0;
  const client = async () => {
    while (next < total) {
      const from = next;
      next = Math.min(total, next + BATCH);
      const count = next - from;
      const body = [];
      for (let i = from; i < from + count; i++) {
        body.push(
          email(`u${i}@d${i % destinations}.example`, i, {
            lane: "bulk",
            ...(backlog ? { scheduled_at: releaseAt } : {}),
          }),
        );
      }
      const res = await fetch(`${bench.url}/emails/batch`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      if (res.ok) accepted += count;
      else {
        intakeErrors += count;
        firstError ??= `${res.status} ${await res.text()}`;
      }
      await res.body?.cancel();
    }
  };
  await Promise.all(Array.from({ length: concurrency }, client));
  intakeDone = performance.now();
})();

const probeSent = new Map<number, number>();
let probes = 0;
const probeTimer = setInterval(async () => {
  const k = probes++;
  const to = `p${k}@d${(k * 20) % destinations}.example`;
  probeSent.set(k, performance.now());
  const res = await fetch(`${bench.url}/emails`, {
    method: "POST",
    headers,
    body: JSON.stringify({ ...email(to, k), subject: `Probe #${k}` }),
  });
  if (!res.ok) probeSent.delete(k);
  await res.body?.cancel();
}, 1_000);

const marks = [0.5, 0.9, 0.99, 0.999, 1];
const reached = new Map<number, number>();
const peaks = { rssMb: 0, dbMb: 0, connections: 0, roleRss: new Map<string, number>() };
const cpuBefore = await usage(bench.pids());
let last = { at: performance.now(), unique: 0 };
let cpuAt99: number | null = null;
let lastProgress = performance.now();
console.log("  time  accepted  delivered  rate/s  open conns  RSS MB  DB MB");
for (;;) {
  await Bun.sleep(SAMPLE_MS);
  const now = performance.now();
  const st = sink.stats();
  const u = await usage(bench.pids());
  const db = await dbSize();
  for (const [role, pid] of bench.roles()) {
    const r = (await usage([pid])).rssMb;
    peaks.roleRss.set(role, Math.max(peaks.roleRss.get(role) ?? 0, r));
  }
  peaks.rssMb = Math.max(peaks.rssMb, u.rssMb);
  peaks.dbMb = Math.max(peaks.dbMb, db);
  peaks.connections = Math.max(peaks.connections, st.peak);
  for (const m of marks) {
    if (!reached.has(m) && st.unique >= Math.ceil(total * m)) reached.set(m, now - started);
  }
  if (cpuAt99 === null && reached.has(0.99)) cpuAt99 = u.cpuMs;
  const rate = ((st.unique - last.unique) * 1_000) / (now - last.at);
  console.log(
    `  ${String(Math.round((now - started) / 1_000)).padStart(4)}s  ${String(accepted).padStart(8)}  ${String(st.unique).padStart(9)}  ${String(Math.round(rate)).padStart(6)}  ${String(st.active).padStart(10)}  ${String(Math.round(u.rssMb)).padStart(6)}  ${String(Math.round(db)).padStart(5)}`,
  );
  if (st.unique > last.unique) lastProgress = now;
  last = { at: now, unique: st.unique };
  if (st.unique + intakeErrors >= total && intakeDone) break;
  const at999 = reached.get(0.999);
  if (at999 !== undefined && now - started - at999 > TAIL_MS) {
    console.log("  stopped: 2 minutes after 99.9% were delivered");
    break;
  }
  if (now - lastProgress > STALL_MS) {
    console.log("  stopped: no progress for 40 minutes");
    break;
  }
}
clearInterval(probeTimer);
await intake;

const st = sink.stats();
const cpuAfter = await usage(bench.pids());
const db = new Database(`${bench.dir}/data/bunzzle.db`, { readonly: true });
const jobStates = db
  .query<{ state: string; n: number }, []>("SELECT state, count(*) AS n FROM jobs GROUP BY state")
  .all();
const rcptStates = db
  .query<{ status: string; n: number }, []>(
    "SELECT status, count(*) AS n FROM recipients GROUP BY status",
  )
  .all();
const waiting = db
  .query<
    {
      state: string;
      attempt: number;
      run_after: number | null;
      check_after: number | null;
      last_error: string | null;
    },
    []
  >(
    `SELECT state, attempt, run_after, check_after, last_error FROM jobs
     WHERE state IN ('ready', 'leased', 'unknown') ORDER BY run_after LIMIT 20`,
  )
  .all();
db.close();
const roleCpu = await cpuByRole(bench.roles());
const latencies: number[] = [];
let lost = 0;
for (const [k, at] of probeSent) {
  const got = sink.probeAt(k);
  if (got === undefined) lost++;
  else latencies.push(got - at);
}
latencies.sort((a, b) => a - b);
const secs = (ms: number | undefined) =>
  ms === undefined ? "not reached" : `${(ms / 1_000).toFixed(0)} s`;

console.log("\nresults");
if (firstError) console.log(`  first intake error: ${firstError}`);
console.log(
  `  intake: ${accepted} accepted in ${((intakeDone - started) / 1_000).toFixed(0)} s (${Math.round(accepted / ((intakeDone - started) / 1_000))}/s, batches of ${BATCH}, while delivering), ${intakeErrors} refused`,
);
console.log(
  `  delivered: ${st.unique} of ${total}; ${marks.map((m) => `${m * 100}% at ${secs(reached.get(m))}`).join(", ")}`,
);
console.log(
  backlog
    ? `  backlog: all ${total} due at ${BACKLOG_MS / 1_000} s (intake done at ${((intakeDone - started) / 1_000).toFixed(0)} s); drain to 90% took ${reached.has(0.9) ? (((reached.get(0.9) as number) - BACKLOG_MS) / 1_000).toFixed(0) : "-"} s = ${reached.has(0.9) ? Math.round((total * 0.9) / (((reached.get(0.9) as number) - BACKLOG_MS) / 1_000)) : "-"}/s`
    : `  sustained rate to 90%: ${reached.has(0.9) ? Math.round((total * 0.9) / ((reached.get(0.9) as number) / 1_000)) : "-"}/s`,
);
console.log(
  `  receivers: ${st.greylisted} greylisted, ${st.deferred} deferred with 421, ${st.dropped} connections dropped after the data, ${st.duplicates} duplicates`,
);
console.log(
  `  transactional probes during the backlog: ${latencies.length} delivered, p50 ${pct(latencies, 0.5)} ms, p99 ${pct(latencies, 0.99)} ms, max ${pct(latencies, 1)} ms, ${lost} not delivered`,
);
console.log(
  `  connections: ${st.sessions} sessions, peak ${peaks.connections} open at once, ${st.tlsSessions} with STARTTLS`,
);
console.log(
  `  CPU ${(((cpuAt99 ?? cpuAfter.cpuMs) - cpuBefore.cpuMs) / Math.max(1, Math.ceil(total * 0.99))).toFixed(2)} ms per email up to 99%; by role (s): ${[...roleCpu].map(([r, ms]) => `${r} ${(ms / 1_000).toFixed(0)}`).join(", ")}`,
);
console.log(
  `  memory peak: ${Math.round(peaks.rssMb)} MB RSS summed (${[...peaks.roleRss].map(([r, mb]) => `${r} ${Math.round(mb)}`).join(", ")}); database peak ${Math.round(peaks.dbMb)} MB`,
);
console.log(
  `  jobs left: ${jobStates.map((r) => `${r.state} ${r.n}`).join(", ") || "none"}; recipients: ${rcptStates.map((r) => `${r.status} ${r.n}`).join(", ")}`,
);
for (const w of waiting) {
  const next = w.state === "unknown" ? w.check_after : w.run_after;
  console.log(
    `    waiting: ${w.state}, attempt ${w.attempt}, next try in ${next ? Math.round((next - Date.now()) / 60_000) : "?"} min (${(w.last_error ?? "").slice(0, 120)})`,
  );
}
await bench.stop();
if (intakeErrors > 0 || st.unique < total) process.exitCode = 1;
