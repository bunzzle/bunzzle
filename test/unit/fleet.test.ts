import { expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import { claim } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import type { DeliveryTransport } from "../../src/delivery/transport.ts";
import { Shaper } from "../../src/shaping/shaper.ts";

function harness(ready: Set<string>) {
  const clock = manualClock();
  const db = openDatabase({ path: ":memory:" });
  const log = createLogger("error", {}, () => {});
  const sent: string[] = [];
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
      sent.push(req.source ?? "");
      throw new Error("sent");
    },
  };
  const handle = deliveryHandler({
    db,
    log,
    transport,
    clock,
    shaper: new Shaper({ log, clock }),
    ips: [
      { ip: "203.0.113.1", pool: "main", established: true },
      { ip: "203.0.113.2", pool: "main", established: true },
    ],
    ipReady: (ip) => ready.has(ip),
    ipRetryMs: 10_000,
  });
  let n = 0;
  const run = async () => {
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
  return { run, sent };
}

test("IPs whose node is down are skipped", async () => {
  for (const up of ["203.0.113.1", "203.0.113.2"]) {
    const h = harness(new Set([up]));
    expect(await h.run()).toBe("sent");
    expect(h.sent).toEqual([up]);
  }
});

test("with every IP on a down node, the email waits in the queue", async () => {
  const h = harness(new Set());
  const outcome = await h.run();
  expect(h.sent).toEqual([]);
  expect(JSON.stringify(outcome)).toContain("every source IP is paused");
});
