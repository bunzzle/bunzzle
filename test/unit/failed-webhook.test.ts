import { describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { claim, settle } from "../../src/core/jobs.ts";
import type { Outcome } from "../../src/core/outcome.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";
import { removeQueued } from "../../src/queue/control.ts";
import { projectEvents } from "../../src/webhooks/project.ts";
import { createWebhook } from "../../src/webhooks/store.ts";

const T0 = 1_800_000_000_000;
const DAY = 24 * 3_600_000;

function setup() {
  const db = openDatabase({ path: ":memory:" });
  createWebhook(db, DEFAULT_PROJECT, "https://hooks.example.com/x", ["email.failed"], T0);
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
    T0,
  );
  const sent = () =>
    db
      .query<{ payload: string }, []>(
        "SELECT payload FROM webhook_deliveries WHERE type = 'email.failed'",
      )
      .all()
      .map((r) => (JSON.parse(r.payload) as { data: Record<string, unknown> }).data);
  const failAfter = (outcome: Outcome) => {
    const [job] = claim(db, T0, 1, 60_000);
    if (!job) throw new Error("nothing claimed");
    const now = T0 + 5 * DAY;
    settle(db, job, outcome, now, { retry: defaultRetryPolicy, reconcileMs: 60_000 });
    projectEvents(db, now);
    return sent();
  };
  return { db, sent, failAfter };
}

describe("email.failed webhook", () => {
  test("after a wait for a pool with no source IP: the code and the text naming the pool", () => {
    const s = setup();
    const reason = "no source IP is configured in the pool acme";
    expect(s.failAfter({ kind: "requeue", reason, delayMs: 300_000, aged: true })).toEqual([
      expect.objectContaining({ reason: "retries_exhausted", message: reason }),
    ]);
  });

  test("after a wait for a down node", () => {
    const s = setup();
    const reason = "node node-a is down (203.0.113.1)";
    expect(s.failAfter({ kind: "requeue", reason, delayMs: 60_000, aged: true })).toEqual([
      expect.objectContaining({ reason: "retries_exhausted", message: reason }),
    ]);
  });

  test("after retries", () => {
    const s = setup();
    const reason = "x@example.test: 451 4.7.1 try again later";
    expect(s.failAfter({ kind: "defer", reason })).toEqual([
      expect.objectContaining({ reason: "retries_exhausted", message: reason }),
    ]);
  });

  test("after an operator fails it", () => {
    const s = setup();
    removeQueued(s.db, null, { domain: "example.test" }, "fail", "domain retired", T0, false);
    projectEvents(s.db, T0);
    expect(s.sent()).toEqual([
      expect.objectContaining({ reason: "operator", message: "domain retired" }),
    ]);
  });

  test("the text is capped at 4096 characters", () => {
    const s = setup();
    const [message] = s.failAfter({ kind: "defer", reason: "x".repeat(5000) });
    expect(String(message?.["message"]).length).toBe(4096);
  });
});
