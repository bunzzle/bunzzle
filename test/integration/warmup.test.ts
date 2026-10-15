import { afterAll, beforeAll, expect, test } from "bun:test";
import { manualClock } from "../../src/core/clock.ts";
import { claim, settle } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { sealBody } from "../../src/crypto/envelope.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail, recipientsOf } from "../../src/delivery/queue.ts";
import { localTransport } from "../../src/delivery/transport.ts";
import { generateKeyFile, sealKeyFile } from "../../src/dkim/keys.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import { DAY_MS, getWarmup, rollover } from "../../src/ips/warmup.ts";
import { Shaper } from "../../src/shaping/shaper.ts";
import { Signer } from "../../src/signer/signer.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-warmup-${crypto.randomUUID()}`;
const T0 = 20_100 * DAY_MS + 9 * 3_600_000;
let dns: FakeDns;
let mx: FakeMx;

beforeAll(async () => {
  await Bun.$`mkdir -p ${dir}`.quiet();
  dns = await startFakeDns({
    "example.test": { MX: [[10, "mx.example.test"]] },
    "mx.example.test": { A: ["127.0.0.1"] },
  });
  mx = startFakeMx();
});

afterAll(async () => {
  dns.stop();
  mx.stop();
  await Bun.$`rm -rf ${dir}`.quiet();
});

test("a new IP sends only its warm-up budget, waits for tomorrow, then gets more", async () => {
  const master = await masterKeyFrom(generateMasterKey());
  await Bun.write(
    `${dir}/dkim.json`,
    JSON.stringify(await sealKeyFile(await generateKeyFile("bunzzle.test", "w1"), master)),
  );
  const clock = manualClock(T0);
  const db = openDatabase({ path: ":memory:" });
  const lines: string[] = [];
  const log = createLogger("info", {}, (l) => lines.push(l));
  const signer = await Signer.create({
    master,
    keystorePath: `${dir}/epochs.json`,
    dkimKeyFiles: [`${dir}/dkim.json`],
    clock,
  });
  const ips = [{ ip: "127.0.0.1", pool: "main", established: false }];
  const handle = deliveryHandler({
    db,
    log,
    clock,
    ips,
    shaper: new Shaper({
      log,
      clock,
      limits: () => ({ connections: 10, ratePerSec: 10_000, perConnection: 100 }),
    }),
    transport: localTransport(
      {
        resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
        ehloName: "out.bunzzle.test",
        port: mx.port,
        allowPrivate: true,
        tlsCa: TEST_CA,
        sources: ["127.0.0.1"],
        timeouts: { greeting: 2_000, quit: 200 },
      },
      (id, body, o) => signer.open(id, body, o),
    ),
  });
  const key = await signer.epochKey();
  const ids: string[] = [];
  for (let i = 0; i < 150; i++) {
    const id = Bun.randomUUIDv7();
    const body = await sealBody(key, id, `From: a@bunzzle.test\r\nSubject: ${i}\r\n\r\nhi\r\n`);
    ids.push(
      enqueueEmail(
        db,
        {
          id,
          body,
          from: "a@bunzzle.test",
          recipients: [`u${i}@example.test`],
          smtpUtf8: false,
          requireTls: false,
        },
        clock.now(),
      ),
    );
  }
  const run = async () => {
    for (;;) {
      clock.advance(1_000);
      const jobs = claim(db, clock.now(), 10, 3_600_000);
      if (jobs.length === 0) return;
      const outcomes = await Promise.all(jobs.map((j) => handle(j)));
      jobs.forEach((j, i) => {
        settle(db, j, outcomes[i] as NonNullable<(typeof outcomes)[number]>, clock.now(), {
          retry: defaultRetryPolicy,
          reconcileMs: 900_000,
        });
      });
    }
  };
  const delivered = () =>
    ids.filter((id) => recipientsOf(db, id)[0]?.status === "delivered").length;

  await run();
  expect(delivered()).toBe(100);
  const waiting = ids.map((id) => recipientsOf(db, id)[0]).find((r) => r?.status !== "delivered");
  expect(waiting?.reply).toContain(
    "warm-up: today's other budget for 127.0.0.1 (day 1, 100) is used up",
  );
  expect(getWarmup(db, "127.0.0.1", "other")).toMatchObject({
    budget: 100,
    sent: 100,
    state: "warming",
  });

  clock.advance(DAY_MS - 30_000);
  rollover(db, clock.now(), log);
  expect(getWarmup(db, "127.0.0.1", "other")).toMatchObject({ budget: 200, sent: 0 });
  expect(lines.some((l) => l.includes("warm-up day evaluated") && l.includes("healthy"))).toBe(
    true,
  );
  await run();
  expect(delivered()).toBe(150);
  expect(mx.sessions.flatMap((s) => s.messages)).toHaveLength(150);
}, 60_000);
