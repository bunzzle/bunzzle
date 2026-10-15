import type { Database } from "bun:sqlite";
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { manualClock } from "../../src/core/clock.ts";
import { eventsFor } from "../../src/core/events.ts";
import { type ClaimedJob, claim, resendUnresolved, settle } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { getPath } from "../../src/delivery/paths.ts";
import { enqueueEmail, recipientsOf } from "../../src/delivery/queue.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, type MxScenario, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const HOUR = 60 * MIN;
const DATA = "From: a@bunzzle.test\r\nTo: x@example.test\r\nSubject: Hi\r\n\r\nHello\r\n";
const SITE = "mx.example.test";

let dns: FakeDns;
let mx: FakeMx | null = null;
const alerts: string[] = [];

beforeAll(async () => {
  dns = await startFakeDns({
    "example.test": { MX: [[10, "mx.example.test"]] },
    "mx.example.test": { A: ["127.0.0.1"] },
    "other.test": { MX: [[10, "mx.other.test"]] },
    "mx.other.test": { A: ["127.0.0.1"] },
  });
});

afterAll(() => dns.stop());

afterEach(() => {
  mx?.stop();
  mx = null;
  alerts.length = 0;
});

function setup(scenario: MxScenario = {}) {
  mx = startFakeMx(scenario);
  const db: Database = openDatabase({ path: ":memory:" });
  const clock = manualClock(T0);
  const log = createLogger("warn", {}, (line) => alerts.push(line));
  const handle = deliveryHandler({
    db,
    log,
    clock,
    resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
    ehloName: "out.bunzzle.test",
    port: mx.port,
    allowPrivate: true,
    tlsCa: TEST_CA,
    timeouts: { greeting: 2_000, quit: 200 },
  });
  const send = (recipients: string[], extra: { expiresAt?: number } = {}) =>
    enqueueEmail(
      db,
      {
        from: "a@bunzzle.test",
        recipients,
        data: DATA,
        smtpUtf8: false,
        requireTls: false,
        ...extra,
      },
      clock.now(),
    );
  const settleAll = async (jobs: ClaimedJob[]) => {
    const outcomes = await Promise.all(jobs.map((j) => handle(j)));
    return jobs.map((j, i) =>
      settle(db, j, outcomes[i] as NonNullable<(typeof outcomes)[number]>, clock.now(), {
        retry: defaultRetryPolicy,
        reconcileMs: 15 * MIN,
        random: () => 0.5,
      }),
    );
  };
  const step = async (at: number) => {
    clock.advance(at - clock.now());
    resendUnresolved(db, at);
    return settleAll(claim(db, at, 50, HOUR));
  };
  const statuses = (id: string) =>
    Object.fromEntries(recipientsOf(db, id).map((r) => [r.address, r.status]));
  const job = (id: string) =>
    db.query<Record<string, unknown>, [string]>("SELECT * FROM jobs WHERE id = ?").get(id) ?? {};
  const kinds = (id: string) => eventsFor(db, id).map((e) => e.kind);
  return { db, clock, handle, send, step, settleAll, statuses, job, kinds };
}

const sessions = () => mx?.sessions.length ?? 0;

describe("delivery: one job per recipient domain, a result per recipient", () => {
  test("recipients at one domain share one SMTP transaction", async () => {
    const t = setup();
    const id = t.send(["x@example.test", "y@example.test", "z@other.test"]);
    expect(await t.step(T0)).toEqual(["done", "done"]);
    expect(t.statuses(id)).toEqual({
      "x@example.test": "delivered",
      "y@example.test": "delivered",
      "z@other.test": "delivered",
    });
    const rcpts = mx?.sessions.map((s) => s.commands.filter((c) => c.startsWith("RCPT")).length);
    expect(rcpts?.sort()).toEqual([1, 2]);
    expect(t.kinds(id).filter((k) => k === "attempt")).toHaveLength(2);
  });

  test("550 user unknown: that recipient bounces and would be suppressed, the other is delivered", async () => {
    const t = setup({
      rcpt: (a) => (a.startsWith("nobody") ? "550 5.1.1 User unknown\r\n" : "250 2.1.5 Ok\r\n"),
    });
    const id = t.send(["nobody@example.test", "x@example.test"]);
    expect(await t.step(T0)).toEqual(["done"]);
    const rows = recipientsOf(t.db, id);
    expect(rows.map((r) => [r.address, r.status, r.class, r.suppress])).toEqual([
      ["nobody@example.test", "bounced", "user-unknown", 1],
      ["x@example.test", "delivered", "accepted", 0],
    ]);
    const candidate = eventsFor(t.db, id).find((e) => e.kind === "suppression_candidate");
    expect(candidate?.data).toEqual({ address: "nobody@example.test", class: "user-unknown" });
  });

  test("every recipient rejected: the job is dead, nothing is retried", async () => {
    const t = setup({ rcpt: () => "550 5.1.1 User unknown\r\n" });
    const id = t.send(["nobody@example.test"]);
    expect(await t.step(T0)).toEqual(["dead"]);
    expect(t.statuses(id)).toEqual({ "nobody@example.test": "bounced" });
  });
});

describe("delivery: retries", () => {
  test("greylisted: retried after exactly one minute, then delivered", async () => {
    let seen = 0;
    const t = setup({
      rcpt: () =>
        seen++ === 0 ? "450 4.2.0 Recipient address rejected: Greylisted\r\n" : "250 2.1.5 Ok\r\n",
    });
    const id = t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(t.statuses(id)).toEqual({ "x@example.test": "deferred" });
    expect(t.job(`${id}/example.test`)["run_after"]).toBe(T0 + MIN);
    expect(await t.step(T0 + MIN - 1)).toEqual([]);
    expect(await t.step(T0 + MIN)).toEqual(["done"]);
    expect(t.statuses(id)).toEqual({ "x@example.test": "delivered" });
    expect(recipientsOf(t.db, id)[0]?.attempts).toBe(2);
  });

  test("a server hint sets the next attempt, clamped to one hour", async () => {
    const t = setup({ rcpt: () => "451 4.7.1 Please try again in 3 hours\r\n" });
    const id = t.send(["x@example.test"]);
    await t.step(T0);
    expect(t.job(`${id}/example.test`)["run_after"]).toBe(T0 + HOUR);
  });

  test("per-email expiry: never delivered after expiresAt, recipient failed as expired", async () => {
    const t = setup({ rcpt: () => "451 4.3.0 Local error\r\n" });
    const id = t.send(["x@example.test"], { expiresAt: T0 + 10 * MIN });
    const jid = `${id}/example.test`;
    await t.step(T0);
    await t.step(T0 + MIN);
    expect(t.job(jid)["run_after"]).toBe(T0 + 6 * MIN);
    await t.step(T0 + 6 * MIN);
    expect(t.job(jid)["run_after"]).toBe(T0 + 10 * MIN);
    const before = sessions();
    expect(await t.step(T0 + 10 * MIN)).toEqual(["dead"]);
    expect(sessions()).toBe(before);
    expect(recipientsOf(t.db, id)[0]).toMatchObject({ status: "failed", class: "expired" });
  });

  test("connection lost after the final dot: unknown, reconciled, resent with duplicate_risk", async () => {
    const t = setup({ final: (n) => (n === 0 ? "drop" : "250 2.0.0 Ok\r\n") });
    const id = t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["unknown"]);
    expect(t.statuses(id)).toEqual({ "x@example.test": "unknown" });
    expect(await t.step(T0 + 15 * MIN - 1)).toEqual([]);
    expect(await t.step(T0 + 15 * MIN)).toEqual(["done"]);
    expect(t.kinds(id)).toContain("duplicate_risk");
    expect(t.statuses(id)).toEqual({ "x@example.test": "delivered" });
  });
});

describe("delivery: feedback to the path", () => {
  test("IP blocked: path paused for an hour, recipient untouched, other emails wait without connecting", async () => {
    let blocked = true;
    const t = setup({
      rcpt: (address) =>
        blocked && address.endsWith("@example.test")
          ? "554 5.7.1 Service unavailable; Client host [127.0.0.1] blocked using zen.spamhaus.org\r\n"
          : "250 2.1.5 Ok\r\n",
    });
    const first = t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(recipientsOf(t.db, first)[0]).toMatchObject({
      status: "deferred",
      scope: "reputation",
      suppress: 0,
    });
    expect(getPath(t.db, "default", SITE, T0)).toMatchObject({
      state: "paused",
      until: T0 + HOUR,
      pauses: 1,
    });
    expect(t.kinds(first)).toContain("path_paused");
    expect(t.kinds(first)).not.toContain("suppression_candidate");
    expect(alerts.some((l) => l.includes("path paused"))).toBe(true);

    const before = sessions();
    const second = t.send(["y@example.test"]);
    const other = t.send(["z@other.test"]);
    expect(await t.step(T0 + MIN)).toEqual(["retry", "done"]);
    expect(sessions()).toBe(before + 1);
    expect(t.statuses(second)).toEqual({ "y@example.test": "deferred" });
    expect(t.statuses(other)).toEqual({ "z@other.test": "delivered" });
    expect(t.job(`${second}/example.test`)["run_after"]).toBe(T0 + HOUR);

    blocked = false;
    expect(await t.step(T0 + HOUR)).toEqual(["done", "done"]);
    expect(t.statuses(first)).toEqual({ "x@example.test": "delivered" });
    expect(getPath(t.db, "default", SITE, T0 + HOUR)).toMatchObject({ state: "open", pauses: 0 });
  });

  test("a second block doubles the pause", async () => {
    const t = setup({ greeting: "554 5.7.1 Go away\r\n" });
    t.send(["x@example.test"]);
    await t.step(T0);
    expect(getPath(t.db, "default", SITE, T0).until).toBe(T0 + HOUR);
    await t.step(T0 + HOUR);
    expect(getPath(t.db, "default", SITE, T0 + HOUR).until).toBe(T0 + 3 * HOUR);
  });

  test("421 too many connections: path slowed, one session at a time to that site", async () => {
    let first = true;
    const t = setup({
      greeting: () => {
        if (!first) return "220 mx.example.test ESMTP\r\n";
        first = false;
        return "421 4.7.0 Too many connections from your IP, slow down\r\n";
      },
    });
    const a = t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(getPath(t.db, "default", SITE, T0)).toMatchObject({
      state: "slowed",
      until: T0 + 10 * MIN,
    });
    expect(t.kinds(a)).toContain("path_slowed");

    const b = t.send(["y@example.test"]);
    const c = t.send(["z@example.test"]);
    const before = sessions();
    const results = await t.step(T0 + MIN);
    expect(results.filter((r) => r === "done")).toHaveLength(1);
    expect(results.filter((r) => r === "retry")).toHaveLength(2);
    expect(sessions()).toBe(before + 1);
    const waiting = [a, b, c].flatMap((id) =>
      recipientsOf(t.db, id).filter((r) => r.reply?.includes("slowed")),
    );
    expect(waiting).toHaveLength(2);
  });

  test("DMARC rejection fails the message, alerts, and never suppresses", async () => {
    const t = setup({
      final: "550 5.7.26 Unauthenticated email is not accepted due to domain's DMARC policy\r\n",
    });
    const id = t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["dead"]);
    expect(recipientsOf(t.db, id)[0]).toMatchObject({
      status: "bounced",
      scope: "sender",
      suppress: 0,
    });
    expect(alerts.some((l) => l.includes("sender setup rejected"))).toBe(true);
  });
});
