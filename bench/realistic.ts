import { issue, privateKeyPem } from "../test/support/x509.ts";
import { type Bench, cpuByRole, cpuShare, load, pct, SENDER, startBench, usage } from "./setup.ts";
import { startSink } from "./sink.ts";

const FEATURES = ["large", "recipients", "webhooks", "tracking", "eventlog"] as const;
type Feature = (typeof FEATURES)[number];
const CASES = ["base", "medium", ...FEATURES, "all", "slow", "backlog"];

const name = Bun.argv[2] ?? "base";
if (!CASES.includes(name)) {
  console.log(
    `usage: bun bench/realistic.ts <${CASES.join("|")}> [emails] [destinations] [clients]`,
  );
  process.exit(1);
}
const total = Number(Bun.argv[3] ?? 10_000);
const destinations = Number(Bun.argv[4] ?? 1_000);
const concurrency = Number(Bun.argv[5] ?? 64);
const BACKLOG = Number(Bun.env["BENCH_BACKLOG"] ?? 5_000_000);
const SLOW_MS = Number(Bun.env["BENCH_SLOW_MS"] ?? 2_000);
const RECIPIENTS = 5;
const TRACK_HOST = `links.${SENDER}`;
const STALL_MS = 60_000;
const self = Number((await Bun.$`sh -c 'echo $PPID'`.text()).trim());

const on = new Set<Feature>(name === "all" ? FEATURES : FEATURES.filter((f) => f === name));
const rcpts = on.has("recipients") ? RECIPIENTS : 1;

const links = (n: number) =>
  Array.from({ length: n }, (_, k) => `<a href="https://shop.example/p/${k}">Item ${k}</a>`).join(
    " ",
  );
const smallHtml = `<p>Hi,</p><p>${"Click the link to sign in. ".repeat(40)}</p><p>${links(3)}</p>`;
const largeHtml = `<html><body>${Array.from(
  { length: 100 },
  (_, k) =>
    `<table><tr><td><h2>Section ${k}</h2><p>${"Seasonal picks with free returns. ".repeat(12)}</p><p>${links(1)}</p></td></tr></table>`,
).join("")}</body></html>`.slice(0, 50 * 1024);
const attachment = crypto.getRandomValues(new Uint8Array(100 * 1024)).toBase64();

const message = (bench: Bench, i: number) => ({
  from: `Acme <hello@${SENDER}>`,
  to: Array.from(
    { length: rcpts },
    (_, k) => bench.recipients[(i * rcpts + k) % destinations] as string,
  ),
  subject: `Your order update #${i}`,
  html: on.has("large") || name === "medium" ? largeHtml : smallHtml,
  text: "Your order is on its way. ".repeat(on.has("large") ? 200 : 40),
  ...(on.has("large")
    ? {
        attachments: [
          { filename: "invoice.pdf", content: attachment, content_type: "application/pdf" },
        ],
      }
    : {}),
});

const certs = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-bench-certs-${crypto.randomUUID()}`;
const env: Record<string, string> = {
  BUNZZLE_ANOMALY_FLOOR: "100000000",
  BUNZZLE_PUBLIC_URL: `https://mail.${SENDER}`,
};
if (on.has("tracking")) {
  const cert = await issue({ name: TRACK_HOST, dns: [TRACK_HOST] });
  await Bun.write(`${certs}/track/${TRACK_HOST}/cert.pem`, cert.pem);
  await Bun.write(`${certs}/track/${TRACK_HOST}/key.pem`, await privateKeyPem(cert));
  Object.assign(env, {
    BUNZZLE_CERTS_DIR: certs,
    BUNZZLE_TRACK_HOST: "127.0.0.1",
    BUNZZLE_TRACK_PORT: "0",
  });
}
if (on.has("eventlog")) Object.assign(env, { BUNZZLE_EVENT_LOG: "true" });

const hooks = { count: 0, last: 0 };
const receiver = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  async fetch(req) {
    await req.arrayBuffer();
    hooks.count++;
    hooks.last = performance.now();
    return new Response("ok");
  },
});

const sink = startSink(total + destinations, {
  slowMs: SLOW_MS,
  behavior: () => (name === "slow" ? "slow" : "normal"),
});
const bench = await startBench(destinations, { sink, env });
const headers = { authorization: `Bearer ${bench.token}`, "content-type": "application/json" };
const api = (path: string, method: string, body: unknown) =>
  fetch(`${bench.url}${path}`, { method, headers, body: JSON.stringify(body) });

try {
  if (on.has("tracking")) {
    bench.zone[TRACK_HOST] = { CNAME: `mail.${SENDER}` };
    const res = await api(`/domains/${SENDER}`, "PATCH", {
      tracking: { host: TRACK_HOST, opens: true, clicks: true },
    });
    const set = (await res.json()) as { tracking?: { record?: { status?: string } } };
    if (set.tracking?.record?.status !== "verified") {
      throw new Error(`tracking host not verified: ${JSON.stringify(set)}`);
    }
  }
  if (on.has("webhooks")) {
    const res = await api("/webhooks", "POST", {
      endpoint: `http://127.0.0.1:${receiver.port}/hooks`,
    });
    if (!res.ok) throw new Error(`webhook not created: ${res.status} ${await res.text()}`);
  }

  let backlogLine = "";
  if (name === "backlog") {
    const due = new Date(Date.now() + 24 * 3_600_000).toISOString();
    const started = performance.now();
    let next = 0;
    let refused = 0;
    const client = async () => {
      while (next < BACKLOG) {
        const from = next;
        next = Math.min(BACKLOG, next + 100);
        const body = [];
        for (let i = from; i < next; i++) {
          body.push({
            ...message(bench, i),
            to: [`u${i}@d${i % destinations}.example`],
            lane: "bulk",
            scheduled_at: due,
          });
        }
        const res = await api("/emails/batch", "POST", body);
        if (!res.ok) refused += next - from;
        await res.body?.cancel();
        if (next % 500_000 < 100) {
          console.log(
            `  backlog ${next} queued, ${Math.round((performance.now() - started) / 1_000)} s`,
          );
        }
      }
    };
    await Promise.all(Array.from({ length: 8 }, client));
    const db = Number(
      (await Bun.$`du -sk ${bench.dir}/data`.nothrow().text()).split(/\s+/)[0] ?? 0,
    );
    backlogLine = `  backlog: ${BACKLOG - refused} scheduled for tomorrow in ${Math.round((performance.now() - started) / 1_000)} s, ${refused} refused, database ${(db / 1024 / 1024).toFixed(1)} GB`;
    console.log(backlogLine);
  }

  const warm = Math.ceil(destinations / rcpts);
  await load(bench, warm, concurrency, (i) => message(bench, i));
  while (sink.received() < warm * rcpts) await Bun.sleep(50);
  await Bun.sleep(1_000);

  const base = sink.received();
  const hooksBase = hooks.count;
  const before = await cpuByRole(bench.roles());
  const benchBefore = (await usage([self])).cpuMs;
  const started = performance.now();
  const r = await load(bench, total, concurrency, (i) => message(bench, warm + i));
  const expected = (total - r.errors) * rcpts;
  let last = -1;
  let lastAt = performance.now();
  let peak = 0;
  while (sink.received() - base < expected) {
    await Bun.sleep(50);
    const now = sink.received();
    peak = Math.max(peak, sink.stats().active);
    if (now !== last) {
      last = now;
      lastAt = performance.now();
    } else if (performance.now() - lastAt > STALL_MS) break;
  }
  const seconds = (performance.now() - started) / 1000;
  const after = await cpuByRole(bench.roles());
  const benchAfter = (await usage([self])).cpuMs;
  const delivered = sink.received() - base;
  const emails = delivered / rcpts;

  let hookLine = "";
  if (on.has("webhooks")) {
    let seen = -1;
    while (hooks.count !== seen) {
      seen = hooks.count;
      await Bun.sleep(3_000);
    }
    const lag = Math.max(0, hooks.last - (started + seconds * 1000)) / 1000;
    hookLine = `  webhooks: ${hooks.count - hooksBase} calls (${((hooks.count - hooksBase) / delivered).toFixed(2)} per delivered message), last one ${lag.toFixed(1)} s after the last delivery`;
  }
  const afterHooks = await cpuByRole(bench.roles());
  const logMb = on.has("eventlog")
    ? Number((await Bun.$`du -sk ${bench.dir}/logs`.nothrow().text()).split(/\s+/)[0] ?? 0) / 1024
    : 0;
  const rss = (await usage(bench.pids())).rssMb;

  console.log(
    `realistic benchmark "${name}": ${total} emails x ${rcpts} recipient(s) to ${destinations} destinations, ${on.has("large") ? "50 KB html + 100 KB attachment" : name === "medium" ? "50 KB html" : "2 KB html"}, ${[...on].filter((f) => f !== "large" && f !== "recipients").join(" + ") || "no extras"}${name === "slow" ? `, every receiver ${SLOW_MS} ms per message` : ""}`,
  );
  if (backlogLine) console.log(backlogLine);
  if (r.firstError) console.log(`  first error: ${r.firstError}`);
  console.log(
    `  intake ${Math.round(total / r.seconds)} emails/s (p50 ${pct(r.latencies, 0.5)} ms, p99 ${pct(r.latencies, 0.99)} ms), ${r.errors} refused`,
  );
  console.log(
    `  delivered ${delivered} messages (${Math.round(emails)} emails) in ${seconds.toFixed(1)} s: ${Math.round(delivered / seconds)} messages/s, ${Math.round(emails / seconds)} emails/s`,
  );
  console.log(
    `  rate floor ${(delivered / (destinations * 5)).toFixed(1)} s at 5 messages/s per destination`,
  );
  console.log(`  CPU ms per delivered message by role: ${cpuShare(before, after, delivered)}`);
  if (on.has("webhooks")) {
    console.log(
      `  CPU ms per delivered message by role, webhooks drained: ${cpuShare(before, afterHooks, delivered)}`,
    );
  }
  console.log(
    `  bench process ${((benchAfter - benchBefore) / delivered).toFixed(3)} ms per message; peak open connections ${peak}; RSS ${Math.round(rss)} MB${logMb ? `; event log ${logMb.toFixed(1)} MB` : ""}`,
  );
  if (hookLine) console.log(hookLine);
  if (r.errors > 0 || delivered < expected) process.exitCode = 1;
} finally {
  await bench.stop();
  receiver.stop(true);
  await Bun.$`rm -rf ${certs}`.quiet().nothrow();
}
