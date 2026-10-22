import { expect, test } from "bun:test";
import { DEFAULT_PROJECT, type ProjectId } from "../../src/accounts/projects.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { shredBodies } from "../../src/delivery/queue.ts";
import {
  claimDeliveries,
  createWebhook,
  listDeliveries,
  MAX_RESEND,
  recordAttempt,
  resendDelivery,
  resendRange,
  settleDelivery,
} from "../../src/webhooks/store.ts";

const T0 = Date.UTC(2026, 9, 22, 8);
const OTHER = "other" as ProjectId;

function setup() {
  const db = openDatabase({ path: ":memory:" });
  db.run("INSERT INTO projects (id, name, created_at) VALUES ('other', 'other', 0)");
  const hook = createWebhook(db, DEFAULT_PROJECT, "https://hooks.test/in", [], T0);
  const add = (id: string, state: string, at: number) =>
    db.run(
      `INSERT INTO webhook_deliveries (id, webhook_id, type, payload, state, next_at, created_at, updated_at)
       VALUES (?, ?, 'email.delivered', '{}', ?, ?, ?, ?)`,
      [id, hook.id, state, at, at, at],
    );
  return { db, hook, add };
}

test("every attempt is kept with status, error and duration, oldest first", () => {
  const { db, hook, add } = setup();
  add("d1", "pending", T0);
  for (const [status, error, at] of [
    [503, "endpoint answered 503", T0 + 5_000],
    [null, "connection refused", T0 + 310_000],
    [200, null, T0 + 2_110_000],
  ] as const) {
    const [d] = claimDeliveries(db, at, 10);
    recordAttempt(db, { deliveryId: "d1", at, status, error, durationMs: 40 });
    settleDelivery(db, d as { id: string; attempt: number }, status === 200, error, at);
  }
  const [d] = listDeliveries(db, DEFAULT_PROJECT, hook.id, { limit: 10 }) ?? [];
  expect(d?.state).toBe("done");
  expect(d?.attempts.map((a) => [a.status, a.error])).toEqual([
    [503, "endpoint answered 503"],
    [null, "connection refused"],
    [200, null],
  ]);
  recordAttempt(db, {
    deliveryId: "d1",
    at: T0,
    status: 500,
    error: "x".repeat(2000),
    durationMs: 1,
  });
  const long = listDeliveries(db, DEFAULT_PROJECT, hook.id, { limit: 10 })?.[0]?.attempts.at(-1);
  expect(long?.error?.length).toBe(500);
});

test("filters, pages and keeps other projects out", () => {
  const { db, hook, add } = setup();
  add("a1", "done", T0);
  add("a2", "failed", T0 + 1_000);
  add("a3", "done", T0 + 2_000);
  const ids = (q: Parameters<typeof listDeliveries>[3]) =>
    listDeliveries(db, DEFAULT_PROJECT, hook.id, q)?.map((d) => d.id);
  expect(ids({ limit: 10 })).toEqual(["a3", "a2", "a1"]);
  expect(ids({ limit: 10, failed: true })).toEqual(["a2"]);
  expect(ids({ limit: 10, from: T0 + 1_000, to: T0 + 2_000 })).toEqual(["a2"]);
  expect(ids({ limit: 1, before: "a3" })).toEqual(["a2"]);
  expect(listDeliveries(db, OTHER, hook.id, { limit: 10 })).toBeNull();
  expect(resendDelivery(db, OTHER, hook.id, "a1", T0)).toBe("not-found");
  expect(resendRange(db, OTHER, hook.id, { from: 0, to: T0 * 2, failed: false }, T0)).toBeNull();
});

test("a resend starts the retry schedule again; a delivery in flight cannot be resent", () => {
  const { db, hook, add } = setup();
  add("f1", "failed", T0);
  add("p1", "pending", T0);
  db.run("UPDATE webhook_deliveries SET attempt = 8 WHERE id = 'f1'");
  expect(resendDelivery(db, DEFAULT_PROJECT, hook.id, "p1", T0)).toBe("in-flight");
  expect(resendDelivery(db, DEFAULT_PROJECT, hook.id, "nope", T0)).toBe("not-found");
  expect(resendDelivery(db, DEFAULT_PROJECT, hook.id, "f1", T0 + 9)).toBe("resent");
  const claimed = claimDeliveries(db, T0 + 9, 10).find((d) => d.id === "f1");
  expect(claimed?.attempt).toBe(1);
});

test("a range resends finished deliveries, only failed ones on request, and is capped", () => {
  const { db, hook, add } = setup();
  add("r1", "done", T0);
  add("r2", "failed", T0 + 1);
  add("r3", "pending", T0 + 2);
  add("r4", "done", T0 + 10_000);
  const range = { from: T0, to: T0 + 5_000 };
  expect(resendRange(db, DEFAULT_PROJECT, hook.id, { ...range, failed: true }, T0)).toEqual({
    resent: 1,
  });
  expect(resendRange(db, DEFAULT_PROJECT, hook.id, { ...range, failed: false }, T0)).toEqual({
    resent: 1,
  });
  const insert = db.prepare(
    `INSERT INTO webhook_deliveries (id, webhook_id, type, payload, state, next_at, created_at, updated_at)
     VALUES (?, ?, 'email.delivered', '{}', 'done', 0, ?, 0)`,
  );
  db.transaction(() => {
    for (let i = 0; i <= MAX_RESEND; i++) insert.run(`bulk${i}`, hook.id, T0 + 20_000);
  })();
  expect(
    resendRange(
      db,
      DEFAULT_PROJECT,
      hook.id,
      { from: T0 + 20_000, to: T0 + 20_001, failed: false },
      T0,
    ),
  ).toEqual({ tooMany: MAX_RESEND + 1 });
});

test("attempts go with their delivery when it is pruned", () => {
  const { db, add } = setup();
  add("old", "done", T0);
  recordAttempt(db, { deliveryId: "old", at: T0, status: 200, error: null, durationMs: 3 });
  shredBodies(db, T0 + 31 * 86_400_000, 30 * 86_400_000);
  expect(db.query("SELECT count(*) AS n FROM webhook_attempts").get()).toEqual({ n: 0 });
});
