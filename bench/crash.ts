import { runCrash } from "../test/crash/harness.ts";

const messages = Number(Bun.argv[2] ?? 100_000);
const kills = Number(Bun.argv[3] ?? 20);

console.log(`crash test: ${messages} messages, ${kills} SIGKILLs`);
const r = await runCrash({
  messages,
  kills,
  minRunMs: 150,
  maxRunMs: 700,
  onProgress: (line) => console.log(`  ${line}`),
});
console.log();
console.log(`${r.done} done, ${r.lost} lost, ${r.dead} dead`);
console.log(`acked but missing after a kill: ${r.ackedMissingAfterKill}`);
console.log(
  `deliveries ${r.deliveries}, duplicates ${r.duplicates} (recorded as duplicate_risk: ${r.duplicatesRecorded}, unrecorded: ${r.unrecordedDuplicates})`,
);
console.log(`${r.kills} kills, ${r.seconds} s`);
const ok =
  r.lost === 0 && r.ackedMissingAfterKill === 0 && r.unrecordedDuplicates === 0 && r.dead === 0;
console.log(ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
