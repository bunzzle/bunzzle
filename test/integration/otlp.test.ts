import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
const CALLER = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

interface OtlpSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  attributes: { key: string; value: Record<string, unknown> }[];
  links?: { traceId: string; spanId: string }[];
}

let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let collector: ReturnType<typeof Bun.serve>;
const spans: OtlpSpan[] = [];
const metrics: { name: string }[] = [];
const auth: (string | null)[] = [];

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  return { stdout: stdout.trim(), code };
}

async function until<T>(f: () => T, ok: (v: T) => boolean, ms = 20_000): Promise<T> {
  const end = Date.now() + ms;
  let v = f();
  while (!ok(v) && Date.now() < end) {
    await Bun.sleep(100);
    v = f();
  }
  return v;
}

const attr = (s: OtlpSpan | undefined, key: string) =>
  s?.attributes.find((a) => a.key === key)?.value;

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  collector = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      auth.push(req.headers.get("authorization"));
      const body = (await req.json()) as Record<string, unknown[]>;
      const path = new URL(req.url).pathname;
      if (path === "/v1/traces") {
        for (const rs of body["resourceSpans"] as { scopeSpans: { spans: OtlpSpan[] }[] }[])
          for (const ss of rs.scopeSpans) spans.push(...ss.spans);
      } else if (path === "/v1/metrics") {
        for (const rm of body["resourceMetrics"] as { scopeMetrics: { metrics: [] }[] }[])
          for (const sm of rm.scopeMetrics) metrics.push(...sm.metrics);
      }
      return Response.json({});
    },
  });
  const headers = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-otlp-${crypto.randomUUID()}.txt`;
  await Bun.write(headers, "Authorization=Bearer%20collector-test\n");
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_RETRY_SCALE: "0.001",
    BUNZZLE_OTLP_ENDPOINT: `http://127.0.0.1:${collector.port}/`,
    BUNZZLE_OTLP_HEADERS_FILE: headers,
    BUNZZLE_OTLP_METRICS_INTERVAL: "10",
  });
  await cli("domains", "add", "acme.test");
  const show = await cli("domains", "show", "acme.test");
  for (const m of show.stdout.matchAll(
    /TXT {2}(\S+\._domainkey\.acme\.test)\n\s+(v=DKIM1[^\n]+)/g,
  )) {
    zone[m[1] as string] = { TXT: [m[2] as string] };
  }
  await cli("domains", "verify", "acme.test");
}, 30_000);

afterAll(async () => {
  await served.stop();
  collector.stop(true);
  dns.stop();
  mx.stop();
});

describe("OpenTelemetry export", () => {
  test("intake and delivery share the email's trace; metrics are pushed", async () => {
    const token = (await cli("keys", "create", "--name", "t", "--scope", "send")).stdout
      .split("\n")
      .at(-1) as string;
    const r = await fetch(`${served.url}/emails`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        traceparent: CALLER,
      },
      body: JSON.stringify({
        from: "hello@acme.test",
        to: "user@example.test",
        subject: "Traced",
        text: "Hello",
      }),
    });
    expect(r.status).toBe(200);
    const { id } = (await r.json()) as { id: string };
    const traceId = id.replaceAll("-", "");
    const mine = await until(
      () => spans.filter((s) => s.traceId === traceId),
      (l) => l.some((s) => s.name === "smtp.session"),
    );
    const intake = mine.find((s) => s.name === "email.intake");
    const deliver = mine.find((s) => s.name === "email.deliver");
    const session = mine.find((s) => s.name === "smtp.session");
    expect(intake?.links).toEqual([
      { traceId: "4bf92f3577b34da6a3ce929d0e0e4736", spanId: "00f067aa0ba902b7" },
    ]);
    expect(attr(intake, "bunzzle.recipients")).toEqual({ intValue: "1" });
    expect(attr(deliver, "bunzzle.delivered")).toEqual({ intValue: "1" });
    expect(session?.parentSpanId).toBe(deliver?.spanId);
    expect(attr(session, "network.peer.address")).toEqual({ stringValue: "127.0.0.1" });

    const pushed = await until(
      () => metrics,
      (l) => l.length > 0,
    );
    expect(pushed.map((m) => m.name)).toContain("bunzzle_jobs");
    expect(auth.every((a) => a === "Bearer collector-test")).toBe(true);
  }, 30_000);
});
