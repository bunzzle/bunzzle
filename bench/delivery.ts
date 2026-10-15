import { cpuByRole, cpuShare, email, load, pct, startBench, usage } from "./setup.ts";

const total = Number(Bun.argv[2] ?? 10_000);
const destinations = Number(Bun.argv[3] ?? 500);
const concurrency = Number(Bun.argv[4] ?? 64);

const bench = await startBench(destinations);
try {
  await load(bench, destinations, concurrency, (i) => email(bench.recipients[i] as string, i));
  while (bench.received() < destinations) await Bun.sleep(50);
  const base = bench.received();
  const before = await usage(bench.pids());
  const beforeRoles = await cpuByRole(bench.roles());
  const started = performance.now();
  const r = await load(bench, total, concurrency, (i) =>
    email(bench.recipients[i % destinations] as string, i),
  );
  let last = -1;
  let idle = 0;
  while (bench.received() - base < total - r.errors && idle < 600) {
    await Bun.sleep(50);
    const now = bench.received();
    idle = now === last ? idle + 1 : 0;
    last = now;
  }
  const seconds = (performance.now() - started) / 1000;
  const after = await usage(bench.pids());
  const afterRoles = await cpuByRole(bench.roles());
  if (r.firstError) console.log(`first error: ${r.firstError}`);
  const delivered = bench.received() - base;
  console.log(
    `delivery benchmark: ${total} emails to ${destinations} destinations on a local SMTP sink, STARTTLS + DKIM (2 signatures)`,
  );
  console.log(
    `  intake ${Math.round(total / r.seconds)} emails/s while delivering (p50 ${pct(r.latencies, 0.5)} ms, p99 ${pct(r.latencies, 0.99)} ms)`,
  );
  console.log(
    `  delivered ${delivered} in ${seconds.toFixed(1)} s: ${Math.round(delivered / seconds)} emails/s end to end`,
  );
  console.log(
    `  server CPU ${((after.cpuMs - before.cpuMs) / delivered).toFixed(2)} ms per email (intake + queue + MIME + encryption + DKIM + SMTP + TLS), RSS ${Math.round(after.rssMb)} MB`,
  );
  console.log(`  TLS sessions at the sink: ${bench.tlsSessions()}`);
  console.log(`  CPU ms per email by role: ${cpuShare(beforeRoles, afterRoles, delivered)}`);
  if (r.errors > 0) process.exitCode = 1;
} finally {
  await bench.stop();
}
