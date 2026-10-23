import { expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import { claim } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import type { Outcome } from "../../src/core/outcome.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import type { DeliveryTransport } from "../../src/delivery/transport.ts";
import { choose, type IpDown } from "../../src/ips/warmup.ts";
import { Shaper } from "../../src/shaping/shaper.ts";

const A = "203.0.113.1";
const B = "203.0.113.2";
const MIN = 60_000;
const IPS = [
  { ip: A, pool: "main", established: true },
  { ip: B, pool: "main", established: true },
];

function harness(down: (ip: string, now: number) => IpDown | null) {
  const clock = manualClock();
  const db = openDatabase({ path: ":memory:" });
  const log = createLogger("error", {}, () => {});
  const sent: { source: string; via?: string }[] = [];
  const transport: DeliveryTransport = {
    lookup: async (domain) => ({
      kind: "targets",
      domain,
      mxHosts: ["mx.company.example"],
      implicit: false,
      authenticated: false,
      targets: [{ host: "mx.company.example", preference: 10, address: "192.0.2.1", family: 4 }],
      skipped: [],
    }),
    deliver: async (req) => {
      sent.push({ source: req.source ?? "", ...(req.via ? { via: req.via } : {}) });
      throw new Error("sent");
    },
  };
  const handle = deliveryHandler({
    db,
    log,
    transport,
    clock,
    shaper: new Shaper({ log, clock }),
    ips: IPS,
    relayRoutes: () => ({ targets: [], blocked: true }),
    ipDown: (ip) => down(ip, clock.now()),
  });
  let n = 0;
  const run = async (): Promise<Outcome | string> => {
    enqueueEmail(
      db,
      DEFAULT_PROJECT,
      {
        id: `m${n++}`,
        body: { epoch: 1, wrapped: new Uint8Array(1), body: new Uint8Array(1) },
        from: "a@bunzzle.test",
        recipients: ["x@company.example"],
        smtpUtf8: false,
        requireTls: false,
      },
      clock.now(),
    );
    const [job] = claim(db, clock.now(), 1, 60_000);
    return handle(job as NonNullable<typeof job>).catch((e: Error) => e.message);
  };
  return { run, sent, clock };
}

const nodeDown =
  (ips: string[], ageMs: number) =>
  (ip: string, now: number): IpDown | null =>
    ips.includes(ip) ? { reason: `node node-a is down (${ip})`, since: now - ageMs } : null;

test("an IP whose node is down is skipped", async () => {
  for (const [gone, left] of [
    [A, B],
    [B, A],
  ] as const) {
    const h = harness(nodeDown([gone], 0));
    expect(await h.run()).toBe("sent");
    expect(h.sent).toEqual([{ source: left }]);
  }
});

test("with every IP on a down node, the email waits, names the node and never uses the relay", async () => {
  const h = harness(nodeDown([A, B], 0));
  const outcome = (await h.run()) as Outcome & { delayMs: number; reason: string };
  expect(h.sent).toEqual([]);
  expect(outcome.kind).toBe("requeue");
  expect(outcome.reason).toBe(`node node-a is down (${A}); node node-a is down (${B})`);
  expect(outcome.delayMs).toBe(MIN);
});

test("the wait grows with the outage, from 1 to 10 minutes", async () => {
  for (const [age, delay] of [
    [10_000, MIN],
    [5 * MIN, 5 * MIN],
    [45 * MIN, 10 * MIN],
  ] as const) {
    const h = harness(nodeDown([A, B], age));
    const outcome = (await h.run()) as Outcome & { delayMs: number };
    expect(outcome.delayMs).toBe(delay);
  }
});

test("a down IP next to a receiver-paused IP is a plain wait, not a block", () => {
  const db = openDatabase({ path: ":memory:" });
  const now = 1_000_000_000;
  const result = choose(
    db,
    IPS,
    "transactional",
    "company.example",
    null,
    1,
    now,
    (ip) => (ip === A ? now + 30_000 : null),
    () => false,
    null,
    (ip) => (ip === B ? { reason: `node node-a is down (${B})`, since: now - 5 * MIN } : null),
  );
  expect(result).toEqual({ wait: { delayMs: 30_000, reason: `node node-a is down (${B})` } });
});

test("a receiver block on every IP still allows the relay", async () => {
  const db = openDatabase({ path: ":memory:" });
  const now = 1_000_000_000;
  const result = choose(db, IPS, "transactional", "company.example", null, 1, now, () => now + MIN);
  expect(result).toMatchObject({ wait: { blocked: true } });
});
