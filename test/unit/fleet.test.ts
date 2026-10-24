import { expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import {
  type ClaimedJob,
  claim,
  expireLeases,
  renewLease,
  resendUnresolved,
  settle,
  wakeWaitingOn,
} from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import type { Outcome } from "../../src/core/outcome.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import type { DeliveryTransport } from "../../src/delivery/transport.ts";
import { choose, type IpDown } from "../../src/ips/warmup.ts";
import { collect } from "../../src/metrics/metrics.ts";
import { DeliveryFleet } from "../../src/nodes/fleet.ts";
import type { NodeLinks } from "../../src/nodes/links.ts";
import { Shaper } from "../../src/shaping/shaper.ts";

const A = "203.0.113.1";
const B = "203.0.113.2";
const MIN = 60_000;
const IPS = [
  { ip: A, pool: "main", established: true },
  { ip: B, pool: "main", established: true },
];

function harness(
  down: (ip: string, now: number) => IpDown | null,
  nodeOf?: (source: string) => string | null,
) {
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
    ...(nodeOf ? { nodeOf } : {}),
  });
  const renewed: (string | null | undefined)[] = [];
  let n = 0;
  let last: ClaimedJob | null = null;
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
    const claimed = job as NonNullable<typeof job>;
    last = claimed;
    return handle(claimed, AbortSignal.timeout(60_000), {
      renew: async (node) => {
        renewed.push(node);
        return renewLease(db, claimed, clock.now() + 60_000, clock.now(), node);
      },
    }).catch((e: Error) => e.message);
  };
  return { run, sent, clock, db, renewed, last: () => last as ClaimedJob };
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

test("the lease carries the node the attempt went to, and keeps it through lease expiry", async () => {
  const h = harness(
    () => null,
    (ip) => (ip === A ? "node-a" : null),
  );
  expect(await h.run()).toBe("sent");
  expect(h.sent[0]?.source).toBe(A);
  const row = () =>
    h.db.query<{ state: string; node: string | null }, []>("SELECT state, node FROM jobs").get();
  expect(row()).toEqual({ state: "leased", node: "node-a" });
  h.clock.advance(2 * MIN);
  expect(expireLeases(h.db, h.clock.now(), MIN)).toBe(1);
  expect(row()).toEqual({ state: "unknown", node: "node-a" });
  h.clock.advance(2 * MIN);
  expect(resendUnresolved(h.db, h.clock.now())).toBe(1);
  const [again] = claim(h.db, h.clock.now(), 1, 60_000);
  expect(again).toMatchObject({ node: "node-a", unresolvedAttempt: 1 });
});

test("a send through the local delivery role does not write the lease again", async () => {
  const h = harness(
    () => null,
    () => null,
  );
  expect(await h.run()).toBe("sent");
  expect(h.renewed).toEqual([]);
  expect(h.db.query("SELECT node FROM jobs").get()).toEqual({ node: null });
});

test("node state, delivered count and jobs per node in metrics", async () => {
  const reply = (ips: string[]) => ({
    call: async () => ips.map((ip) => ({ ip })),
    close() {},
  });
  const links = {
    sync() {},
    names: () => ["node-a"],
    client: () => reply([B]),
  } as unknown as NodeLinks;
  const fleet = new DeliveryFleet({
    local: reply([A]) as never,
    links,
    log: createLogger("error", {}, () => {}),
  });
  await fleet.check();
  fleet.delivered("node-a", 3);
  fleet.delivered("local", 1);
  expect(fleet.nodeOf(B)).toBe("node-a");
  expect(fleet.nodeOf(A)).toBeNull();

  const h = harness(
    () => null,
    (ip) => fleet.nodeOf(ip),
  );
  await h.run();
  await h.run();
  const families = collect(h.db, null, [], 0, 0, undefined, null, null, fleet.health());
  const of = (name: string) => families.find((f) => f.name === name)?.samples;
  expect(of("bunzzle_node_up")).toEqual([
    { labels: { node: "local" }, value: 1 },
    { labels: { node: "node-a" }, value: 1 },
  ]);
  expect(of("bunzzle_node_delivered")).toEqual([
    { labels: { node: "local" }, value: 1 },
    { labels: { node: "node-a" }, value: 3 },
  ]);
  const leased = (node: string) =>
    of("bunzzle_node_jobs")?.find(
      (x) => x.labels["node"] === node && x.labels["state"] === "leased",
    )?.value;
  expect((leased("local") ?? 0) + (leased("node-a") ?? 0)).toBe(2);
  expect(leased("node-a")).toBe(h.sent.filter((x) => x.source === B).length);
});

const onNode =
  (nodes: Record<string, string>, ageMs: number) =>
  (ip: string, now: number): IpDown | null => {
    const node = nodes[ip];
    return node ? { reason: `node ${node} is down (${ip})`, since: now - ageMs, node } : null;
  };

const wait = async (h: ReturnType<typeof harness>) => {
  const outcome = (await h.run()) as Outcome;
  expect(outcome.kind).toBe("requeue");
  settle(h.db, h.last(), outcome, h.clock.now(), { retry: defaultRetryPolicy, reconcileMs: MIN });
  return h.last().id;
};

const row = (h: ReturnType<typeof harness>, id: string) =>
  h.db
    .query<{ run_after: number; wait_nodes: string | null }, [string]>(
      "SELECT run_after, wait_nodes FROM jobs WHERE id = ?",
    )
    .get(id);

test("mail waiting on a down node is due as soon as that node is back", async () => {
  const h = harness(onNode({ [A]: "node-a", [B]: "node-a" }, 5 * MIN));
  const id = await wait(h);
  const now = h.clock.now();
  expect(row(h, id)).toEqual({ run_after: now + 5 * MIN, wait_nodes: '["node-a"]' });
  expect(wakeWaitingOn(h.db, "node-b", now)).toBe(0);
  expect(wakeWaitingOn(h.db, "node-a", now)).toBe(1);
  expect(row(h, id)).toEqual({ run_after: now, wait_nodes: null });
  expect(wakeWaitingOn(h.db, "node-a", now)).toBe(0);
});

test("mail waiting on two down nodes wakes when either is back", async () => {
  const h = harness(onNode({ [A]: "node-a", [B]: "node-b" }, 0));
  const id = await wait(h);
  expect(JSON.parse(row(h, id)?.wait_nodes ?? "[]")).toEqual(["node-a", "node-b"]);
  expect(wakeWaitingOn(h.db, "node-b", h.clock.now())).toBe(1);
});

test("mail waiting on another node or for another reason keeps its due time", async () => {
  const h = harness(onNode({ [A]: "node-b", [B]: "node-b" }, 0));
  const onB = await wait(h);
  const other = await wait(h);
  h.db.query("UPDATE jobs SET wait_nodes = NULL WHERE id = ?").run(other);
  const before = [row(h, onB), row(h, other)];
  expect(wakeWaitingOn(h.db, "node-a", h.clock.now())).toBe(0);
  expect([row(h, onB), row(h, other)]).toEqual(before);
});

test("a claim clears the node a job was waiting on", async () => {
  const h = harness(onNode({ [A]: "node-a", [B]: "node-a" }, 0));
  const id = await wait(h);
  h.clock.advance(MIN);
  expect(claim(h.db, h.clock.now(), 1, MIN).map((j) => j.id)).toEqual([id]);
  expect(row(h, id)?.wait_nodes).toBeNull();
});

test("the fleet reports a node once when it comes back", async () => {
  let failing = false;
  const client = {
    call: async () => {
      if (failing) throw new Error("connect refused");
      return [{ ip: B }];
    },
    close() {},
  };
  const links = {
    sync() {},
    names: () => ["node-a"],
    client: () => client,
  } as unknown as NodeLinks;
  const up: string[] = [];
  const fleet = new DeliveryFleet({
    local: { call: async () => [{ ip: A }], close() {} } as never,
    links,
    log: createLogger("error", {}, () => {}),
    onUp: (name) => up.push(name),
  });
  await fleet.check();
  const start = up.length;
  failing = true;
  for (let i = 0; i < 3; i++) await fleet.check();
  expect(fleet.down(B)).not.toBeNull();
  expect(up.length).toBe(start);
  failing = false;
  await fleet.check();
  await fleet.check();
  expect(up.slice(start)).toEqual(["node-a"]);
  expect(fleet.down(B)).toBeNull();
});
