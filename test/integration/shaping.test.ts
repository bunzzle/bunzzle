import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { countByState } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { sealBody } from "../../src/crypto/envelope.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail, recipientsOf } from "../../src/delivery/queue.ts";
import { localTransport } from "../../src/delivery/transport.ts";
import { generateKeyFile, sealKeyFile } from "../../src/dkim/keys.ts";
import { cachingResolver } from "../../src/dns/cache.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import { scaledPolicy } from "../../src/roles/core.ts";
import { Scheduler } from "../../src/scheduler/scheduler.ts";
import { DEFAULT_TUNING } from "../../src/shaping/control.ts";
import type { Limits } from "../../src/shaping/limits.ts";
import { Shaper } from "../../src/shaping/shaper.ts";
import { Signer } from "../../src/signer/signer.ts";
import type { Relay } from "../../src/smtp/deliver.ts";
import { SessionPool } from "../../src/smtp/pool.ts";
import { startSmtpServer } from "../../src/smtpd/server.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, type MxScenario, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const TLS = `${import.meta.dir}/../fixtures/tls`;
const CERT = await Bun.file(`${TLS}/mx.pem`).text();
const KEY = await Bun.file(`${TLS}/mx.key`).text();
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-shaping-${crypto.randomUUID()}`;
const master = await masterKeyFrom(generateMasterKey());
let dns: FakeDns;
let mx: FakeMx | null = null;
const stops: (() => Promise<void>)[] = [];

beforeAll(async () => {
  await Bun.$`mkdir -p ${dir}`.quiet();
  const keys = await sealKeyFile(await generateKeyFile("bunzzle.test", "t1"), master);
  await Bun.write(`${dir}/dkim.json`, JSON.stringify(keys));
  dns = await startFakeDns({
    "example.test": { MX: [[10, "mx.example.test"]] },
    "mx.example.test": { A: ["127.0.0.1"] },
  });
});

afterEach(async () => {
  for (const s of stops.splice(0)) await s();
  mx?.stop();
  mx = null;
});

afterAll(async () => {
  dns.stop();
  await Bun.$`rm -rf ${dir}`.quiet();
});

interface RelayRun {
  relay: Relay;
  routes: { targets: string[]; blocked: boolean };
}

async function pipeline(scenario: MxScenario, limits: Limits, tuning = {}, routed?: RelayRun) {
  mx = startFakeMx(scenario);
  const db = openDatabase({ path: ":memory:" });
  const writer = new Writer(db);
  const lines: Record<string, unknown>[] = [];
  const log = createLogger("info", {}, (line) => lines.push(JSON.parse(line)));
  const signer = await Signer.create({
    master,
    keystorePath: `${dir}/${crypto.randomUUID()}.json`,
    dkimKeyFiles: [`${dir}/dkim.json`],
  });
  const pool = new SessionPool();
  const shaper = new Shaper({
    log,
    limits: () => limits,
    tuning: { ...DEFAULT_TUNING, ...tuning },
  });
  const transport = localTransport(
    {
      resolver: cachingResolver(
        createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
      ),
      ehloName: "out.bunzzle.test",
      port: mx.port,
      allowPrivate: true,
      tlsCa: TEST_CA,
      timeouts: { greeting: 2_000, quit: 200 },
      pool,
      perConnection: () => 100,
      ...(routed ? { relay: routed.relay, relayAll: false } : {}),
    },
    (id, body, o) => signer.open(id, body, o),
  );
  const handle = deliveryHandler({
    db,
    log,
    transport,
    shaper,
    busyRetryMs: 50,
    maxWaitMs: 30_000,
    ...(routed ? { relayRoutes: () => routed.routes } : {}),
  });
  const scheduler = new Scheduler({
    db,
    writer,
    log,
    handle,
    concurrency: 512,
    leaseMs: 120_000,
    reconcileMs: 200,
    sweepMs: 20,
    retry: scaledPolicy(defaultRetryPolicy, 0.0005),
    filter: () => shaper.blocked(),
  });
  const key = await signer.epochKey();
  const add = async (
    n: number,
    lane: "transactional" | "bulk",
    tag: string,
    requireTls = false,
  ) => {
    const emails: { id: string; body: Awaited<ReturnType<typeof sealBody>> }[] = [];
    for (let i = 0; i < n; i++) {
      const id = Bun.randomUUIDv7();
      const data = `From: a@bunzzle.test\r\nTo: x@example.test\r\nSubject: ${tag}-${i}\r\n\r\nHi\r\n`;
      emails.push({ id, body: await sealBody(key, id, data) });
    }
    await writer.run((d) => {
      for (const e of emails) {
        enqueueEmail(
          d,
          DEFAULT_PROJECT,
          {
            ...e,
            from: "a@bunzzle.test",
            recipients: [`${tag}@example.test`],
            smtpUtf8: false,
            requireTls,
            priority: lane === "bulk" ? 5 : 0,
          },
          Date.now(),
        );
      }
    });
    return emails.map((e) => e.id);
  };
  stops.push(async () => {
    shaper.stop();
    await scheduler.stop();
    await pool.closeAll();
    writer.close();
  });
  const changes = () =>
    lines.filter((l) => String(l["msg"]).startsWith("path ")).map((l) => String(l["msg"]).slice(5));
  return { db, scheduler, shaper, add, changes, lines };
}

async function until(cond: () => boolean, ms: number) {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) return false;
    await Bun.sleep(20);
  }
  return true;
}

test(
  "a provider that throttles: halved fast, then a gradual climb, never far above what it accepts",
  async () => {
    const p = await pipeline(
      { maxConcurrent: 2, finalDelayMs: 30 },
      { connections: 8, ratePerSec: 200, perConnection: 100 },
      { holdMs: 300, climbEvery: 10, ignoreRepeatMs: 100 },
    );
    await p.add(300, "transactional", "t");
    await p.scheduler.start();
    expect(await until(() => countByState(p.db).done === 300, 60_000)).toBe(true);
    const changes = p.changes();
    expect(changes[0]).toBe("halved");
    expect(changes).toContain("climbed");
    const view = p.shaper.views()[0];
    const after = view?.changes ?? [];
    expect(Math.max(...after.map((c) => c.connections))).toBeLessThanOrEqual(4);
    expect(mx?.refused()).toBeGreaterThan(0);
    expect(mx?.peak()).toBeLessThanOrEqual(2);
    console.log(
      `throttle demo: ${changes.join(" → ")}; refused ${mx?.refused()} connections; ended at ${view?.connections} connections, ${view?.rate}/s`,
    );
  },
  { timeout: 90_000 },
);

test(
  "blocked for a while: paused, one probe at a time, then a slow restart and climb",
  async () => {
    let blockedUntil = Date.now() + 600;
    const p = await pipeline(
      {
        rcpt: () =>
          Date.now() < blockedUntil
            ? "554 5.7.1 Service unavailable; Client host [127.0.0.1] blocked using zen.spamhaus.org\r\n"
            : "250 2.1.5 Ok\r\n",
      },
      { connections: 4, ratePerSec: 100, perConnection: 100 },
      { firstPauseMs: 250, maxPauseMs: 2_000, climbEvery: 5 },
    );
    await p.add(60, "transactional", "t");
    await p.scheduler.start();
    expect(await until(() => countByState(p.db).done === 60, 60_000)).toBe(true);
    const changes = p.changes();
    expect(changes[0]).toBe("paused");
    expect(changes).toContain("probing");
    expect(changes).toContain("probe-ok");
    expect(changes.indexOf("climbed")).toBeGreaterThan(changes.indexOf("probe-ok"));
    const suppressed = p.db
      .query("SELECT count(*) AS n FROM recipients WHERE suppress = 1")
      .get() as {
      n: number;
    };
    expect(suppressed.n).toBe(0);
    console.log(`block demo: ${changes.join(" → ")}`);
    blockedUntil = 0;
  },
  { timeout: 90_000 },
);

test(
  "a password reset overtakes 10,000 queued newsletters",
  async () => {
    const p = await pipeline(
      { finalDelayMs: 5 },
      { connections: 4, ratePerSec: 100, perConnection: 100 },
    );
    await p.add(10_000, "bulk", "news");
    await p.scheduler.start();
    await Bun.sleep(500);
    const queuedAt = Date.now();
    const [reset] = await p.add(1, "transactional", "reset");
    expect(
      await until(() => recipientsOf(p.db, reset as string)[0]?.status === "delivered", 10_000),
    ).toBe(true);
    const took = Date.now() - queuedAt;
    const bulkDone = (
      p.db
        .query(
          "SELECT count(*) AS n FROM recipients WHERE address = 'news@example.test' AND status = 'delivered'",
        )
        .get() as { n: number }
    ).n;
    expect(took).toBeLessThan(250);
    expect(bulkDone).toBeLessThan(500);
    const attempts = p.db.query("SELECT max(attempt) AS m FROM jobs").get() as { m: number };
    expect(attempts.m).toBeLessThanOrEqual(1);
    console.log(
      `lane demo: reset delivered ${took} ms after it was queued, behind ${10_000 - bulkDone} newsletters still waiting`,
    );
  },
  { timeout: 120_000 },
);

function relayServer() {
  const received: string[] = [];
  const server = startSmtpServer({
    hostname: "127.0.0.1",
    port: 0,
    name: "relay.example.test",
    banner: "relay",
    tls: { cert: CERT, key: KEY },
    implicitTls: false,
    requireTls: true,
    requireAuth: true,
    blocking: null,
    hooks: {
      auth: async (password) => (password === "s3cret" ? { user: "app" } : null),
      sender: async () => null,
      recipient: async () => null,
      message: async (rcpts) => {
        received.push(...rcpts);
        return { code: 250, text: "2.0.0 relayed" };
      },
    },
  });
  stops.push(async () => server.stop());
  const relay: Relay = {
    host: "mx.example.test",
    port: server.port,
    implicitTls: false,
    username: "app",
    password: "s3cret",
  };
  return { relay, received };
}

const delivered = (db: { query: (sql: string) => { get(): unknown } }, address: string) =>
  (
    db
      .query(
        `SELECT count(*) AS n FROM recipients WHERE address = '${address}' AND status = 'delivered'`,
      )
      .get() as { n: number }
  ).n;

test(
  "blocked: mail goes through the relay while the path is paused, back to direct after the probe",
  async () => {
    let blockedUntil = Date.now() + 600;
    const { relay, received } = relayServer();
    const p = await pipeline(
      {
        rcpt: () =>
          Date.now() < blockedUntil
            ? "554 5.7.1 Service unavailable; Client host [127.0.0.1] blocked using zen.spamhaus.org\r\n"
            : "250 2.1.5 Ok\r\n",
      },
      { connections: 4, ratePerSec: 100, perConnection: 100 },
      { firstPauseMs: 250, maxPauseMs: 2_000, climbEvery: 5 },
      { relay, routes: { targets: [], blocked: true } },
    );
    await p.add(40, "transactional", "t");
    await p.add(5, "transactional", "secure", true);
    await p.scheduler.start();
    expect(
      await until(() => countByState(p.db).done + countByState(p.db).dead === 45, 60_000),
    ).toBe(true);
    const changes = p.changes();
    expect(changes[0]).toBe("paused");
    expect(changes).toContain("probe-ok");
    expect(received.filter((r) => r === "t@example.test").length).toBeGreaterThan(0);
    expect(received).not.toContain("secure@example.test");
    expect(delivered(p.db, "t@example.test")).toBe(40);
    expect(countByState(p.db).dead).toBe(5);
    blockedUntil = 0;
    const direct = mx?.sessions.reduce((n, s) => n + s.messages.length, 0) ?? 0;
    await p.add(10, "transactional", "after");
    expect(await until(() => countByState(p.db).done === 50, 30_000)).toBe(true);
    expect(received).not.toContain("after@example.test");
    expect(mx?.sessions.reduce((n, s) => n + s.messages.length, 0)).toBe(direct + 10);
    console.log(
      `fallback demo: ${changes.join(" → ")}; ${received.length} through the relay, ${direct + 10} direct`,
    );
  },
  { timeout: 90_000 },
);

test("a destination routed to the relay never goes direct", async () => {
  const { relay, received } = relayServer();
  const p = await pipeline(
    {},
    { connections: 4, ratePerSec: 100, perConnection: 100 },
    {},
    { relay, routes: { targets: ["example.test"], blocked: false } },
  );
  await p.add(10, "transactional", "r");
  await p.scheduler.start();
  expect(await until(() => countByState(p.db).done === 10, 30_000)).toBe(true);
  expect(received.filter((r) => r === "r@example.test")).toHaveLength(10);
  expect(mx?.sessions.reduce((n, s) => n + s.messages.length, 0)).toBe(0);
  const attempt = p.db.query("SELECT data FROM events WHERE kind = 'attempt' LIMIT 1").get() as {
    data: string;
  };
  expect(JSON.parse(attempt.data).via).toBe("relay");
});
