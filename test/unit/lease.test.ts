import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import { claim } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import type { DeliveryTransport } from "../../src/delivery/transport.ts";
import { leaseTimes } from "../../src/roles/core.ts";
import { Shaper } from "../../src/shaping/shaper.ts";

function setup(lookupMs: number) {
  const clock = manualClock();
  const db = openDatabase({ path: ":memory:" });
  const log = createLogger("error", {}, () => {});
  let sends = 0;
  const transport: DeliveryTransport = {
    lookup: async (domain) => {
      clock.advance(lookupMs);
      return {
        kind: "targets",
        domain,
        mxHosts: ["mx.example.test"],
        implicit: false,
        authenticated: false,
        targets: [{ host: "mx.example.test", preference: 10, address: "192.0.2.1", family: 4 }],
        skipped: [],
      };
    },
    deliver: async () => {
      sends++;
      throw new Error("sent");
    },
  };
  const handle = deliveryHandler({ db, log, transport, clock, shaper: new Shaper({ log, clock }) });
  enqueueEmail(
    db,
    DEFAULT_PROJECT,
    {
      id: "m",
      body: { epoch: 1, wrapped: new Uint8Array(1), body: new Uint8Array(1) },
      from: "a@bunzzle.test",
      recipients: ["x@example.test"],
      smtpUtf8: false,
      requireTls: false,
    },
    clock.now(),
  );
  const [job] = claim(db, clock.now(), 1, 60_000);
  if (!job) throw new Error("nothing claimed");
  return { handle, job, sends: () => sends };
}

describe("lease while waiting for a delivery slot", () => {
  test("a job whose lease was lost while waiting is requeued, not delivered", async () => {
    const s = setup(2_000);
    let renewals = 0;
    const outcome = await s.handle(s.job, undefined, {
      renew: async () => {
        renewals++;
        return false;
      },
    });
    expect(outcome).toMatchObject({ kind: "requeue", reason: "lease lost while waiting" });
    expect(renewals).toBe(1);
    expect(s.sends()).toBe(0);
  });

  test("no renewal without a wait", async () => {
    const s = setup(0);
    let renewals = 0;
    const outcome = s.handle(s.job, undefined, {
      renew: async () => {
        renewals++;
        return true;
      },
    });
    await expect(outcome).rejects.toThrow("sent");
    expect(renewals).toBe(0);
    expect(s.sends()).toBe(1);
  });

  test("the longest wait for a slot stays under a third of the lease", () => {
    const { leaseMs, maxWaitMs } = leaseTimes(1);
    expect(leaseMs).toBe(45 * 60_000);
    expect(maxWaitMs * 3).toBeLessThanOrEqual(leaseMs);
    for (const scale of [0.1, 0.01, 0.001, 0.0001]) {
      const t = leaseTimes(scale);
      expect(t.maxWaitMs * 2).toBeLessThanOrEqual(t.leaseMs);
    }
  });
});
