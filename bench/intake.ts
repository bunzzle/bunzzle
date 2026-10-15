import { cpuByRole, cpuShare, email, load, pct, startBench, usage } from "./setup.ts";

const total = Number(Bun.argv[2] ?? 20_000);
const concurrency = Number(Bun.argv[3] ?? 64);

const bench = await startBench(1);
const later = new Date(Date.now() + 48 * 3_600_000).toISOString();
try {
  await load(bench, 500, concurrency, (i) =>
    email(bench.recipients[0] as string, i, { scheduled_at: later }),
  );
  const before = await usage(bench.pids());
  const beforeRoles = await cpuByRole(bench.roles());
  const r = await load(bench, total, concurrency, (i) =>
    email(bench.recipients[0] as string, i, { scheduled_at: later }),
  );
  const after = await usage(bench.pids());
  const afterRoles = await cpuByRole(bench.roles());
  if (r.firstError) console.log(`first error: ${r.firstError}`);
  console.log(
    `intake benchmark: ${total} emails through POST /emails, ${concurrency} concurrent clients`,
  );
  console.log(
    `  every email: authenticated, validated, MIME built, encrypted, committed to SQLite`,
  );
  console.log(
    `  ${Math.round(total / r.seconds)} emails/s  (p50 ${pct(r.latencies, 0.5)} ms, p99 ${pct(r.latencies, 0.99)} ms, ${r.errors} errors)`,
  );
  console.log(
    `  server CPU ${((after.cpuMs - before.cpuMs) / total).toFixed(2)} ms per email, RSS ${Math.round(after.rssMb)} MB for six processes with ${total + 500} queued`,
  );
  console.log(`  CPU ms per email by role: ${cpuShare(beforeRoles, afterRoles, total)}`);
  if (r.errors > 0) process.exitCode = 1;
} finally {
  await bench.stop();
}
