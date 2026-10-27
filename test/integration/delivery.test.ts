import type { Database } from "bun:sqlite";
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { manualClock } from "../../src/core/clock.ts";
import { eventsFor } from "../../src/core/events.ts";
import { type ClaimedJob, claim, resendUnresolved, settle } from "../../src/core/jobs.ts";
import { createLogger } from "../../src/core/log.ts";
import { defaultRetryPolicy } from "../../src/core/retry.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { sealBody } from "../../src/crypto/envelope.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { deliveryHandler } from "../../src/delivery/handler.ts";
import { enqueueEmail, recipientsOf, shredBodies } from "../../src/delivery/queue.ts";
import { localTransport } from "../../src/delivery/transport.ts";
import { generateKeyFile, sealKeyFile } from "../../src/dkim/keys.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import { deliverRequestWire, requestFromWire, requestToWire } from "../../src/roles/wire.ts";
import { Shaper } from "../../src/shaping/shaper.ts";
import { Signer, SignerError } from "../../src/signer/signer.ts";
import { memoryBodies } from "../support/bodies.ts";
import { verifyDkim } from "../support/dkim-verify.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, type MxScenario, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const HOUR = 60 * MIN;
const DATA = "From: a@bunzzle.test\r\nTo: x@example.test\r\nSubject: Hi\r\n\r\nHello\r\n";
const PATH = "default|mx.example.test";

let dns: FakeDns;
let mx: FakeMx | null = null;
const alerts: string[] = [];
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-delivery-${crypto.randomUUID()}`;
const master = await masterKeyFrom(generateMasterKey());
const keyFile = await generateKeyFile("bunzzle.test", "t1");

beforeAll(async () => {
  await Bun.$`mkdir -p ${dir}`.quiet();
  await Bun.write(`${dir}/dkim.json`, JSON.stringify(await sealKeyFile(keyFile, master)));
  dns = await startFakeDns({
    "example.test": { MX: [[10, "mx.example.test"]] },
    "mx.example.test": { A: ["127.0.0.1"] },
    "other.test": { MX: [[10, "mx.other.test"]] },
    "mx.other.test": { A: ["127.0.0.1"] },
  });
});

afterAll(async () => {
  dns.stop();
  await Bun.$`rm -rf ${dir}`.quiet();
});

afterEach(() => {
  mx?.stop();
  mx = null;
  alerts.length = 0;
});

async function setup(scenario: MxScenario = {}) {
  mx = startFakeMx(scenario);
  const db: Database = openDatabase({ path: ":memory:" });
  const clock = manualClock(T0);
  const log = createLogger("warn", {}, (line) => alerts.push(line));
  const signer = await Signer.create({
    master,
    keystorePath: `${dir}/${crypto.randomUUID()}-epochs.json`,
    dkimKeyFiles: [`${dir}/dkim.json`],
    clock,
  });
  const transport = localTransport(
    {
      resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
      ehloName: "out.bunzzle.test",
      port: mx.port,
      allowPrivate: true,
      tlsCa: TEST_CA,
      timeouts: { greeting: 2_000, quit: 200 },
    },
    (id, body, o) => signer.open(id, body, o),
  );
  const shaper = new Shaper({
    log,
    clock,
    limits: () => ({ connections: 10, ratePerSec: 1000, perConnection: 100 }),
  });
  const bodies = memoryBodies();
  const handle = deliveryHandler({ db, bodies, log, clock, transport, shaper });
  const send = async (recipients: string[], extra: { expiresAt?: number } = {}) => {
    const id = Bun.randomUUIDv7();
    const body = await sealBody(await signer.epochKey(), id, DATA);
    const size = await bodies.write(id, body);
    return enqueueEmail(
      db,
      DEFAULT_PROJECT,
      {
        id,
        body: { epoch: body.epoch, size },
        from: "a@bunzzle.test",
        recipients,
        smtpUtf8: false,
        requireTls: false,
        ...extra,
      },
      clock.now(),
    );
  };
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
  return { db, bodies, clock, signer, shaper, handle, send, step, settleAll, statuses, job, kinds };
}

const sessions = () => mx?.sessions.length ?? 0;

describe("delivery: one job per recipient domain, a result per recipient", () => {
  test("recipients at one domain share one SMTP transaction", async () => {
    const t = await setup();
    const id = await t.send(["x@example.test", "y@example.test", "z@other.test"]);
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
    const t = await setup({
      rcpt: (a) => (a.startsWith("nobody") ? "550 5.1.1 User unknown\r\n" : "250 2.1.5 Ok\r\n"),
    });
    const id = await t.send(["nobody@example.test", "x@example.test"]);
    expect(await t.step(T0)).toEqual(["done"]);
    const rows = recipientsOf(t.db, id);
    expect(rows.map((r) => [r.address, r.status, r.class, r.suppress])).toEqual([
      ["nobody@example.test", "bounced", "user-unknown", 1],
      ["x@example.test", "delivered", "accepted", 0],
    ]);
    const candidate = eventsFor(t.db, id).find((e) => e.kind === "address_suppressed");
    expect(candidate?.data).toEqual({
      address: "nobody@example.test",
      reason: "hard-bounce",
      scope: "all",
      class: "user-unknown",
    });
    expect(
      t.db
        .query("SELECT reason, scope FROM suppressions WHERE address = 'nobody@example.test'")
        .get(),
    ).toEqual({ reason: "hard-bounce", scope: "all" });
  });

  test("every recipient rejected: the job is dead, nothing is retried", async () => {
    const t = await setup({ rcpt: () => "550 5.1.1 User unknown\r\n" });
    const id = await t.send(["nobody@example.test"]);
    expect(await t.step(T0)).toEqual(["dead"]);
    expect(t.statuses(id)).toEqual({ "nobody@example.test": "bounced" });
  });
});

describe("delivery: retries", () => {
  test("greylisted: retried after exactly one minute, then delivered", async () => {
    let seen = 0;
    const t = await setup({
      rcpt: () =>
        seen++ === 0 ? "450 4.2.0 Recipient address rejected: Greylisted\r\n" : "250 2.1.5 Ok\r\n",
    });
    const id = await t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(t.statuses(id)).toEqual({ "x@example.test": "deferred" });
    expect(t.job(`${id}/example.test`)["run_after"]).toBe(T0 + MIN);
    expect(await t.step(T0 + MIN - 1)).toEqual([]);
    expect(await t.step(T0 + MIN)).toEqual(["done"]);
    expect(t.statuses(id)).toEqual({ "x@example.test": "delivered" });
    expect(recipientsOf(t.db, id)[0]?.attempts).toBe(2);
  });

  test("a server hint sets the next attempt, clamped to one hour", async () => {
    const t = await setup({ rcpt: () => "451 4.7.1 Please try again in 3 hours\r\n" });
    const id = await t.send(["x@example.test"]);
    await t.step(T0);
    expect(t.job(`${id}/example.test`)["run_after"]).toBe(T0 + HOUR);
  });

  test("per-email expiry: never delivered after expiresAt, recipient failed as expired", async () => {
    const t = await setup({ rcpt: () => "451 4.3.0 Local error\r\n" });
    const id = await t.send(["x@example.test"], { expiresAt: T0 + 10 * MIN });
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
    const t = await setup({ final: (n) => (n === 0 ? "drop" : "250 2.0.0 Ok\r\n") });
    const id = await t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["unknown"]);
    expect(t.statuses(id)).toEqual({ "x@example.test": "unknown" });
    expect(await t.step(T0 + 15 * MIN - 1)).toEqual([]);
    expect(await t.step(T0 + 15 * MIN)).toEqual(["done"]);
    expect(t.kinds(id)).toContain("duplicate_risk");
    expect(t.statuses(id)).toEqual({ "x@example.test": "delivered" });
  });
});

describe("delivery: feedback to the path (H2)", () => {
  const view = (t: { shaper: Shaper }) => t.shaper.views().find((v) => v.key === PATH);

  test("IP blocked: path paused 15 min, recipient untouched, others requeued without connecting, one probe, then slow restart", async () => {
    let blocked = true;
    const t = await setup({
      rcpt: (address) =>
        blocked && address.endsWith("@example.test")
          ? "554 5.7.1 Service unavailable; Client host [127.0.0.1] blocked using zen.spamhaus.org\r\n"
          : "250 2.1.5 Ok\r\n",
    });
    const first = await t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(recipientsOf(t.db, first)[0]).toMatchObject({
      status: "deferred",
      scope: "reputation",
      suppress: 0,
    });
    expect(view(t)).toMatchObject({ mode: "paused", until: T0 + 15 * MIN });
    expect(t.job(`${first}/example.test`)["run_after"]).toBe(T0 + 15 * MIN);
    expect(t.kinds(first)).toContain("path_paused");
    expect(t.kinds(first)).not.toContain("address_suppressed");
    expect(alerts.some((l) => l.includes("path paused"))).toBe(true);

    const before = sessions();
    const second = await t.send(["y@example.test"]);
    const other = await t.send(["z@other.test"]);
    expect((await t.step(T0 + MIN)).sort()).toEqual(["done", "requeued"]);
    expect(sessions()).toBe(before + 1);
    expect(recipientsOf(t.db, second)[0]?.reply).toContain("paused");
    expect(t.statuses(other)).toEqual({ "z@other.test": "delivered" });
    expect(t.job(`${second}/example.test`)).toMatchObject({ run_after: T0 + 15 * MIN, attempt: 0 });

    blocked = false;
    expect((await t.step(T0 + 15 * MIN)).sort()).toEqual(["done", "requeued"]);
    expect(view(t)).toMatchObject({ mode: "normal", connections: 1, rate: 50 });
    expect(await t.step(T0 + 16 * MIN)).toEqual(["done"]);
    expect(t.statuses(first)).toEqual({ "x@example.test": "delivered" });
    expect(t.statuses(second)).toEqual({ "y@example.test": "delivered" });
    expect(view(t)?.changes.map((c) => c.what)).toEqual(["paused", "probing", "probe-ok"]);
  });

  test("a failed probe doubles the pause", async () => {
    const t = await setup({ greeting: "554 5.7.1 Go away\r\n" });
    await t.send(["x@example.test"]);
    await t.step(T0);
    expect(view(t)?.until).toBe(T0 + 15 * MIN);
    await t.step(T0 + 15 * MIN);
    expect(view(t)).toMatchObject({ mode: "paused", until: T0 + 45 * MIN });
    expect(view(t)?.changes.map((c) => c.what)).toEqual(["paused", "probing", "probe-failed"]);
  });

  test("421 too many connections: rate and connections halved and held", async () => {
    let first = true;
    const t = await setup({
      greeting: () => {
        if (!first) return "220 mx.example.test ESMTP\r\n";
        first = false;
        return "421 4.7.0 Too many connections from your IP, slow down\r\n";
      },
    });
    const a = await t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(view(t)).toMatchObject({ mode: "held", rate: 500, connections: 5 });
    expect(view(t)?.changes[0]).toMatchObject({ what: "halved" });
    expect(t.kinds(a)).toContain("path_slowed");
    expect(alerts.some((l) => l.includes("path halved"))).toBe(true);
    expect(await t.step(T0 + MIN)).toEqual(["done"]);
  });

  test("DMARC rejection fails the message, alerts, and never suppresses", async () => {
    const t = await setup({
      final: "550 5.7.26 Unauthenticated email is not accepted due to domain's DMARC policy\r\n",
    });
    const id = await t.send(["x@example.test"]);
    expect(await t.step(T0)).toEqual(["dead"]);
    expect(recipientsOf(t.db, id)[0]).toMatchObject({
      status: "bounced",
      scope: "sender",
      suppress: 0,
    });
    expect(alerts.some((l) => l.includes("sender setup rejected"))).toBe(true);
  });
});

describe("delivery: encryption at rest and crypto-shredding", () => {
  const publicKeys = () =>
    Object.fromEntries(
      keyFile.keys.map((k) => [
        k.selector,
        { algorithm: k.algorithm, key: Uint8Array.fromBase64(k.publicKey) },
      ]),
    );

  test("the signer decrypts and DKIM-signs at delivery time, both signatures verify", async () => {
    const t = await setup();
    await t.send(["x@example.test"]);
    await t.step(T0);
    const received = mx?.sessions[0]?.messages[0] ?? "";
    expect(received).toStartWith("DKIM-Signature:");
    const verdicts = await verifyDkim(received, publicKeys());
    expect(verdicts.map((v) => [v.selector, v.ok])).toEqual([
      ["t1r", true],
      ["t1e", true],
    ]);
  });

  test("the body is never stored in plain text, not in the database file nor its WAL", async () => {
    const path = `${dir}/${crypto.randomUUID()}.db`;
    const db = openDatabase({ path });
    const t = await setup();
    const marker = `secret-${crypto.randomUUID()}`;
    const id = Bun.randomUUIDv7();
    const body = await sealBody(await t.signer.epochKey(), id, DATA.replace("Hello", marker));
    enqueueEmail(
      db,
      DEFAULT_PROJECT,
      {
        id,
        body: { epoch: body.epoch, size: body.body.length },
        from: "a@bunzzle.test",
        recipients: ["x@example.test"],
        smtpUtf8: false,
        requireTls: false,
      },
      T0,
    );
    const bytes = async (p: string) =>
      (await Bun.file(p).exists())
        ? new TextDecoder("latin1").decode(await Bun.file(p).bytes())
        : "";
    const onDisk = (await bytes(path)) + (await bytes(`${path}-wal`));
    expect(onDisk.length).toBeGreaterThan(0);
    expect(onDisk.includes(marker)).toBe(false);
    expect(onDisk.includes("x@example.test")).toBe(true);
    expect((await t.signer.open(id, body)).data).toContain(marker);
    db.close();
  });

  test("after retention, a backup copied earlier can no longer be read", async () => {
    const t = await setup();
    const id = await t.send(["x@example.test"]);
    await t.step(T0);
    const backup = t.bodies.files.get(id);
    if (!backup) throw new Error("no body stored");
    const copied = {
      epoch: backup.epoch,
      wrapped: new Uint8Array(backup.wrapped),
      body: new Uint8Array(backup.body),
    };
    expect((await t.signer.open(id, copied)).data).toContain("Hello");

    t.clock.advance(31 * 24 * HOUR);
    expect(await t.signer.shred(30)).toEqual([copied.epoch]);
    expect(shredBodies(t.db, t.clock.now(), 30 * 24 * HOUR)).toEqual([id]);
    expect(t.kinds(id)).toContain("shredded");
    expect(t.db.query("SELECT 1 FROM body_files WHERE message_id = ?").get(id)).toBeNull();
    expect(t.db.query("SELECT epoch FROM body_trash WHERE message_id = ?").get(id)).toEqual({
      epoch: copied.epoch,
    });
    const err = await t.signer.open(id, copied).catch((e: SignerError) => e);
    expect(err).toBeInstanceOf(SignerError);
    expect((err as SignerError).code).toBe("epoch-gone");
  });

  test("bodies of email still being retried are never shredded", async () => {
    const t = await setup({ rcpt: () => "451 4.3.0 Local error\r\n" });
    const id = await t.send(["x@example.test"]);
    await t.step(T0);
    expect(shredBodies(t.db, T0 + 40 * 24 * HOUR, 30 * 24 * HOUR)).toEqual([]);
    expect(t.db.query("SELECT 1 FROM body_files WHERE message_id = ?").get(id)).not.toBeNull();
  });

  test("an email from a domain the signer has no key for is never sent unsigned", async () => {
    const t = await setup();
    const id = Bun.randomUUIDv7();
    const body = await sealBody(
      await t.signer.epochKey(),
      id,
      DATA.replace("a@bunzzle.test", "ceo@other.test"),
    );
    const size = await t.bodies.write(id, body);
    enqueueEmail(
      t.db,
      DEFAULT_PROJECT,
      {
        id,
        body: { epoch: body.epoch, size },
        from: "ceo@other.test",
        recipients: ["x@example.test"],
        smtpUtf8: false,
        requireTls: false,
      },
      T0,
    );
    expect(await t.step(T0)).toEqual(["retry"]);
    expect(mx?.sessions.length).toBe(0);
    expect(recipientsOf(t.db, id)[0]?.reply).toContain("no DKIM key for other.test");
  });
});

describe("delivery: through a delivery node", () => {
  test("a delivery role with no signer sends the message core opened, DKIM-signed", async () => {
    const t = await setup();
    const node = localTransport(
      {
        resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
        ehloName: "out.bunzzle.test",
        port: mx?.port ?? 0,
        allowPrivate: true,
        tlsCa: TEST_CA,
        timeouts: { greeting: 2_000, quit: 200 },
      },
      async () => {
        throw new Error("no signer on this machine");
      },
    );
    const id = Bun.randomUUIDv7();
    const body = await sealBody(await t.signer.epochKey(), id, DATA);
    const opened = await t.signer.open(id, body, { lane: "transactional", bounceDomain: null });
    const sent = JSON.parse(
      JSON.stringify(
        requestToWire({
          key: `${id}#1`,
          recall: null,
          messageId: id,
          domain: "example.test",
          destination: await node.lookup("example.test"),
          from: "a@bunzzle.test",
          recipients: ["x@example.test"],
          smtpUtf8: false,
          requireTls: false,
          opened,
        }),
      ),
    );
    expect(sent.body).toBeUndefined();
    const report = await node.deliver(requestFromWire(deliverRequestWire.parse(sent)));
    expect(report.recipients.map((r) => r.status)).toEqual(["delivered"]);
    expect(mx?.sessions[0]?.messages[0] ?? "").toStartWith("DKIM-Signature:");
  });
  test("a send through an egress needs a source IP and a link certificate", async () => {
    const t = await setup();
    const node = localTransport(
      {
        resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
        ehloName: "out.bunzzle.test",
        port: mx?.port ?? 0,
        allowPrivate: true,
        sources: ["127.0.0.1"],
        egressVia: () => "this delivery role has no link certificate yet",
      },
      async () => {
        throw new Error("no signer on this machine");
      },
    );
    const id = Bun.randomUUIDv7();
    const body = await sealBody(await t.signer.epochKey(), id, DATA);
    const opened = await t.signer.open(id, body, { lane: "transactional", bounceDomain: null });
    const egress = {
      name: "edge-a",
      address: "203.0.113.9:7466",
      pin: `sha256/${"A".repeat(43)}=`,
    };
    const ask = async (source?: string) => {
      const wire = JSON.parse(
        JSON.stringify(
          requestToWire({
            key: `${id}#1`,
            recall: null,
            messageId: id,
            domain: "example.test",
            destination: await node.lookup("example.test"),
            from: "a@bunzzle.test",
            recipients: ["x@example.test"],
            smtpUtf8: false,
            requireTls: false,
            opened,
            egress,
            ...(source ? { source } : {}),
          }),
        ),
      );
      expect(deliverRequestWire.parse(wire).egress).toEqual(egress);
      return (await node.deliver(requestFromWire(deliverRequestWire.parse(wire)))).recipients;
    };
    expect((await ask("127.0.0.1"))[0]?.reply).toContain("no link certificate yet");
    expect((await ask())[0]?.reply).toContain("a send through edge-a needs a source IP");
    expect(mx?.sessions.length ?? 0).toBe(0);
  });
});
