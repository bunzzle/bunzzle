import { startFakeDns, type Zone } from "../test/support/fake-dns.ts";
import { startFakeMx } from "../test/support/fake-mx.ts";
import { startServe } from "../test/support/serve.ts";

const MAIN = `${import.meta.dir}/../src/cli/main.ts`;
export const SENDER = "bench.test";

export interface BenchSink {
  port: number;
  received(): number;
  tlsSessions(): number;
  stop(): void;
}

export interface Bench {
  url: string;
  token: string;
  recipients: string[];
  dir: string;
  received(): number;
  tlsSessions(): number;
  pids(): number[];
  roles(): Map<string, number>;
  stop(): Promise<void>;
}

export async function startBench(
  destinations: number,
  o: { sink?: BenchSink; env?: Record<string, string> } = {},
): Promise<Bench> {
  const zone: Zone = {};
  const recipients: string[] = [];
  for (let i = 0; i < destinations; i++) {
    zone[`d${i}.example`] = { MX: [[10, `mx.d${i}.example`]] };
    zone[`mx.d${i}.example`] = { A: ["127.0.0.1"] };
    recipients.push(`user@d${i}.example`);
  }
  const dns = await startFakeDns(zone);
  const sink: BenchSink =
    o.sink ??
    (() => {
      const mx = startFakeMx();
      return {
        port: mx.port,
        received: () => mx.sessions.reduce((n, s) => n + s.messages.length, 0),
        tlsSessions: () => mx.sessions.filter((s) => s.tls).length,
        stop: () => mx.stop(),
      };
    })();
  const served = await startServe({
    BUNZZLE_MASTER_KEY: (await Bun.$`bun ${MAIN} master-key`.text()).trim(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(sink.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "mail.bench.test",
    ...o.env,
  });
  const cli = async (...args: string[]) =>
    (
      await Bun.$`bun ${MAIN} ${args}`
        .cwd(served.dir)
        .env({
          PATH: Bun.env["PATH"] ?? "",
          BUNZZLE_RUN_DIR: `${served.dir}/run`,
        })
        .text()
    ).trim();
  const token = (
    await cli("keys", "create", "--name", "bench", "--scope", "full", "--rate-limit", "10000")
  )
    .split("\n")
    .pop() as string;
  await cli("projects", "limits", "default", "--new-recipients-auto", "off");
  const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  const domain = (await (
    await fetch(`${served.url}/domains`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: SENDER }),
    })
  ).json()) as { records: { record: string; name: string; value: string }[] };
  for (const r of domain.records) if (r.record === "DKIM") zone[r.name] = { TXT: [r.value] };
  await fetch(`${served.url}/domains/${SENDER}/verify`, { method: "POST", headers });
  return {
    url: served.url,
    token,
    recipients,
    dir: served.dir,
    received: () => sink.received(),
    tlsSessions: () => sink.tlsSessions(),
    pids: () => [served.proc.pid, ...served.pids.values()],
    roles: () => new Map([["supervisor", served.proc.pid], ...served.pids]),
    async stop() {
      await served.stop();
      sink.stop();
      dns.stop();
    },
  };
}

export async function usage(pids: number[]): Promise<{ cpuMs: number; rssMb: number }> {
  const out = await Bun.$`ps -o time=,rss= -p ${pids.join(",")}`.nothrow().text();
  let cpuMs = 0;
  let rssKb = 0;
  for (const line of out.trim().split("\n")) {
    const [time = "0", rss = "0"] = line.trim().split(/\s+/);
    const parts = time.split(/[:-]/).map(Number);
    let seconds = 0;
    for (const p of parts) seconds = seconds * 60 + p;
    cpuMs += seconds * 1000;
    rssKb += Number(rss);
  }
  return { cpuMs, rssMb: rssKb / 1024 };
}

export async function cpuByRole(roles: Map<string, number>): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  for (const [role, pid] of roles) out.set(role, (await usage([pid])).cpuMs);
  return out;
}

export function cpuShare(before: Map<string, number>, after: Map<string, number>, n: number) {
  return [...after]
    .map(([role, ms]) => `${role} ${((ms - (before.get(role) ?? 0)) / n).toFixed(3)}`)
    .join(", ");
}

export interface Load {
  seconds: number;
  ids: string[];
  latencies: number[];
  errors: number;
  firstError: string | null;
}

export async function load(
  bench: Bench,
  total: number,
  concurrency: number,
  body: (i: number) => Record<string, unknown>,
): Promise<Load> {
  const headers = { authorization: `Bearer ${bench.token}`, "content-type": "application/json" };
  const latencies: number[] = [];
  const ids: string[] = [];
  let errors = 0;
  let firstError: string | null = null;
  let next = 0;
  const started = performance.now();
  const client = async () => {
    while (next < total) {
      const i = next++;
      const t = performance.now();
      const res = await fetch(`${bench.url}/emails`, {
        method: "POST",
        headers,
        body: JSON.stringify(body(i)),
      });
      const json = (await res.json()) as { id?: string };
      latencies.push(performance.now() - t);
      if (res.ok && json.id) ids.push(json.id);
      else {
        errors++;
        firstError ??= `${res.status} ${JSON.stringify(json)}`;
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, client));
  latencies.sort((a, b) => a - b);
  return { seconds: (performance.now() - started) / 1000, ids, latencies, errors, firstError };
}

export const pct = (sorted: number[], p: number) =>
  (sorted[Math.floor((sorted.length - 1) * p)] ?? 0).toFixed(1);

export function email(to: string, i: number, extra: Record<string, unknown> = {}) {
  return {
    from: `Acme <hello@${SENDER}>`,
    to: [to],
    subject: `Your sign-in link #${i}`,
    html: `<p>Hi,</p><p>${"Click the link to sign in. ".repeat(40)}</p>`,
    text: "Click the link to sign in. ".repeat(40),
    ...extra,
  };
}
