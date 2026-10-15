import { afterEach, describe, expect, test } from "bun:test";
import { createResolver } from "../../src/dns/resolver.ts";
import { deliver } from "../../src/smtp/deliver.ts";
import { SessionPool } from "../../src/smtp/pool.ts";
import { dotStuff, runSession, type SessionInput } from "../../src/smtp/session.ts";
import { startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, type MxScenario, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const MESSAGE =
  "From: a@bunzzle.com\r\nTo: b@example.test\r\nSubject: Hi\r\n\r\nHello\r\n.leading dot\r\n";

let mx: FakeMx | null = null;
const cleanups: (() => void)[] = [];

afterEach(() => {
  mx?.stop();
  mx = null;
  for (const c of cleanups.splice(0)) c();
});

function session(scenario: MxScenario, overrides: Partial<SessionInput> = {}) {
  mx = startFakeMx(scenario);
  return runSession({
    host: "mx.example.test",
    address: "127.0.0.1",
    port: mx.port,
    ehloName: "out.bunzzle.test",
    policy: { rule: "opportunistic", required: false },
    from: "a@bunzzle.com",
    recipients: ["b@example.test"],
    data: MESSAGE,
    smtpUtf8: false,
    tlsCa: TEST_CA,
    timeouts: { greeting: 1000, quit: 200 },
    ...overrides,
  });
}

const commandsOf = () => mx?.sessions.flatMap((s) => s.commands) ?? [];

describe("SMTP session", () => {
  test("delivers over verified TLS with pipelining", async () => {
    const r = await session({});
    expect(r.phase).toBe("done");
    expect(r.error).toBeNull();
    expect(r.tls).toMatchObject({ status: "verified", rule: "opportunistic", error: null });
    expect(r.tls.version).toMatch(/^TLSv1\.[23]$/);
    expect(r.recipients).toEqual([
      {
        address: "b@example.test",
        status: "delivered",
        phase: "dot",
        code: 250,
        enhanced: "2.0.0",
        reply: "250 Ok: queued as 12345",
      },
    ]);
    expect(mx?.sessions[0]?.tls).toBe(true);
    expect(mx?.sessions[0]?.messages).toEqual([MESSAGE]);
    expect(commandsOf()).toEqual([
      "EHLO out.bunzzle.test",
      "STARTTLS",
      "EHLO out.bunzzle.test",
      `MAIL FROM:<a@bunzzle.com> SIZE=${MESSAGE.length}`,
      "RCPT TO:<b@example.test>",
      "DATA",
      "QUIT",
    ]);
  });

  test("dot-stuffs lines that start with a dot", () => {
    expect(dotStuff("a\r\n.b\r\n..c")).toBe("a\r\n..b\r\n...c\r\n.\r\n");
  });

  test("untrusted certificate: still encrypted, recorded as unverified", async () => {
    const r = await session({}, { tlsCa: undefined as unknown as string });
    expect(r.phase).toBe("done");
    expect(r.tls.status).toBe("unverified");
    expect(r.tls.error).toBeTruthy();
    expect(mx?.sessions[0]?.tls).toBe(true);
  });

  test("certificate for another name is unverified", async () => {
    const r = await session({}, { host: "other.example.test" });
    expect(r.tls.status).toBe("unverified");
    expect(r.tls.error).toBe("ERR_TLS_CERT_ALTNAME_INVALID");
  });

  test("required TLS with an unverified certificate defers before MAIL", async () => {
    const r = await session(
      {},
      { tlsCa: undefined as unknown as string, policy: { rule: "provider", required: true } },
    );
    expect(r.phase).toBe("starttls");
    expect(r.tryNext).toBe(true);
    expect(r.recipients[0]).toMatchObject({ status: "deferred", enhanced: "4.7.5" });
    expect(commandsOf().some((c) => c.startsWith("MAIL"))).toBe(false);
  });

  test("required TLS without STARTTLS defers and never sends in plain text", async () => {
    const r = await session(
      { extensions: ["PIPELINING"] },
      { policy: { rule: "requiretls", required: true } },
    );
    expect(r.recipients[0]?.status).toBe("deferred");
    expect(r.error).toContain("does not offer STARTTLS");
    expect(commandsOf().some((c) => c.startsWith("MAIL"))).toBe(false);
  });

  test("opportunistic without STARTTLS sends in plain text, recorded as none", async () => {
    const r = await session({ extensions: ["PIPELINING", "8BITMIME"] });
    expect(r.phase).toBe("done");
    expect(r.tls.status).toBe("none");
  });

  test("data injected after the STARTTLS reply aborts the session", async () => {
    const r = await session({ injectAfterStarttls: true });
    expect(r.phase).toBe("starttls");
    expect(r.error).toContain("before the TLS handshake");
    expect(r.recipients[0]?.status).toBe("deferred");
    expect(commandsOf().some((c) => c.startsWith("MAIL"))).toBe(false);
  });

  test("per-recipient results: one greylisted, one accepted", async () => {
    const r = await session(
      {
        rcpt: (a) =>
          a.startsWith("grey") ? "450 4.2.0 Greylisted, try again later\r\n" : "250 2.1.5 Ok\r\n",
      },
      { recipients: ["grey@example.test", "b@example.test"] },
    );
    expect(r.recipients.map((x) => [x.address, x.status, x.enhanced])).toEqual([
      ["grey@example.test", "deferred", "4.2.0"],
      ["b@example.test", "delivered", "2.0.0"],
    ]);
  });

  test("all recipients rejected: no message is sent", async () => {
    const r = await session({ rcpt: () => "550 5.1.1 User unknown\r\n" });
    expect(r.phase).toBe("rcpt");
    expect(r.recipients[0]).toMatchObject({ status: "bounced", code: 550, enhanced: "5.1.1" });
    expect(mx?.sessions[0]?.messages).toEqual([]);
  });

  test("MAIL 421 defers and allows the next MX", async () => {
    const r = await session({ mail: "421 4.7.0 Try again later\r\n" });
    expect(r.phase).toBe("mail");
    expect(r.tryNext).toBe(true);
    expect(r.recipients[0]?.status).toBe("deferred");
  });

  test("other MAIL temporary errors stay with this MX", async () => {
    const r = await session({ mail: "451 4.3.0 Local error\r\n" });
    expect(r.tryNext).toBe(false);
    expect(r.recipients[0]).toMatchObject({ status: "deferred", enhanced: "4.3.0" });
  });

  test("MAIL 550 bounces and stops", async () => {
    const r = await session({ mail: "550 5.7.1 Sender rejected\r\n" });
    expect(r.tryNext).toBe(false);
    expect(r.recipients[0]).toMatchObject({ status: "bounced", enhanced: "5.7.1" });
  });

  test("greeting error moves on to the next MX", async () => {
    const r = await session({ greeting: "554 5.7.1 Go away\r\n" });
    expect(r.phase).toBe("greeting");
    expect(r.tryNext).toBe(true);
  });

  test("final reply 552 bounces the accepted recipients", async () => {
    const r = await session({ final: "552 5.3.4 Message too big\r\n" });
    expect(r.recipients[0]).toMatchObject({ status: "bounced", phase: "dot", enhanced: "5.3.4" });
  });

  test("connection lost after the final dot is unknown, never retried on another MX", async () => {
    const r = await session({ final: "drop" });
    expect(r.phase).toBe("dot");
    expect(r.tryNext).toBe(false);
    expect(r.recipients[0]?.status).toBe("unknown");
    expect(mx?.sessions[0]?.messages).toHaveLength(1);
  });

  test("without PIPELINING the commands go one by one", async () => {
    const r = await session({ extensions: ["STARTTLS"] });
    expect(r.phase).toBe("done");
    expect(commandsOf().slice(3)).toEqual([
      "MAIL FROM:<a@bunzzle.com>",
      "RCPT TO:<b@example.test>",
      "DATA",
      "QUIT",
    ]);
  });

  test("message larger than the server's SIZE bounces before MAIL", async () => {
    const r = await session({ extensions: ["SIZE 10", "STARTTLS"] });
    expect(r.recipients[0]).toMatchObject({ status: "bounced", enhanced: "5.3.4" });
    expect(r.error).toContain("at most 10");
    expect(commandsOf().some((c) => c.startsWith("MAIL"))).toBe(false);
  });

  test("SMTPUTF8 message to a server without SMTPUTF8 bounces", async () => {
    const r = await session({ extensions: ["STARTTLS"] }, { smtpUtf8: true });
    expect(r.recipients[0]).toMatchObject({ status: "bounced", enhanced: "5.6.7" });
  });

  test("SMTPUTF8 message declares it on MAIL FROM", async () => {
    await session({}, { smtpUtf8: true });
    expect(commandsOf().find((c) => c.startsWith("MAIL"))).toContain("BODY=8BITMIME SMTPUTF8");
  });

  test("falls back to HELO when EHLO is not supported", async () => {
    const r = await session({ ehlo: "502 5.5.2 Command not recognized\r\n" });
    expect(r.phase).toBe("done");
    expect(r.tls.status).toBe("none");
    expect(commandsOf()[1]).toBe("HELO out.bunzzle.test");
  });

  test("a silent server times out at the greeting deadline", async () => {
    const started = Date.now();
    const r = await session({ greeting: "" }, { timeouts: { greeting: 300 } });
    expect(r.phase).toBe("greeting");
    expect(r.error).toContain("timed out");
    expect(r.recipients[0]?.enhanced).toBe("4.4.2");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  test("a dripping server cannot extend the reply deadline", async () => {
    mx = null;
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open(s) {
          const text = "220 slowly but surely ESMTP\r\n";
          let i = 0;
          const timer = setInterval(() => {
            if (i >= text.length) return clearInterval(timer);
            s.write(text[i++] as string);
          }, 40);
          cleanups.push(() => clearInterval(timer));
        },
        data() {},
      },
    });
    cleanups.push(() => server.stop(true));
    const r = await runSession({
      host: "mx.example.test",
      address: "127.0.0.1",
      port: server.port,
      ehloName: "out.bunzzle.test",
      policy: { rule: "opportunistic", required: false },
      from: "a@bunzzle.com",
      recipients: ["b@example.test"],
      data: MESSAGE,
      smtpUtf8: false,
      timeouts: { greeting: 400, quit: 100 },
    });
    expect(r.phase).toBe("greeting");
    expect(r.error).toContain("timed out");
  });
});

describe("Bun socket behaviour we depend on", () => {
  test("localAddress selects the source IP and refuses addresses we do not own", async () => {
    const ok = await session({}, { localAddress: "127.0.0.1" });
    expect(ok.phase).toBe("done");
    mx?.stop();
    const bad = await session({}, { localAddress: "192.0.2.1" });
    expect(bad.phase).toBe("connect");
    expect(bad.recipients[0]).toMatchObject({ status: "deferred", enhanced: "4.4.1" });
  });
});

describe("deliver", () => {
  test("looks up MX, skips a failing host and delivers on the next one", async () => {
    mx = startFakeMx({
      greeting: (n) => (n === 0 ? "421 4.3.2 Busy\r\n" : "220 mx.example.test ESMTP\r\n"),
    });
    const dns = await startFakeDns({
      "example.test": {
        MX: [
          [10, "mx.example.test"],
          [20, "mx2.example.test"],
        ],
      },
      "mx.example.test": { A: ["127.0.0.1"] },
      "mx2.example.test": { A: ["127.0.0.1"] },
    });
    cleanups.push(() => dns.stop());
    const report = await deliver(
      {
        domain: "example.test",
        from: "a@bunzzle.com",
        recipients: ["b@example.test"],
        data: MESSAGE,
        smtpUtf8: false,
      },
      {
        resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
        ehloName: "out.bunzzle.test",
        port: mx.port,
        allowPrivate: true,
        tlsCa: TEST_CA,
      },
    );
    expect(report.sessions.map((s) => [s.host, s.phase])).toEqual([
      ["mx.example.test", "greeting"],
      ["mx2.example.test", "done"],
    ]);
    expect(report.policy).toEqual({ rule: "opportunistic", required: false });
    expect(report.recipients[0]?.status).toBe("delivered");
    expect(report.sessions[1]?.tls.status).toBe("unverified");
  });

  test("null MX bounces every recipient without connecting", async () => {
    const dns = await startFakeDns({ "nullmx.test": { MX: [[0, ""]] } });
    cleanups.push(() => dns.stop());
    const report = await deliver(
      {
        domain: "nullmx.test",
        from: "a@bunzzle.com",
        recipients: ["x@nullmx.test"],
        data: MESSAGE,
        smtpUtf8: false,
      },
      {
        resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
        ehloName: "x",
      },
    );
    expect(report.sessions).toEqual([]);
    expect(report.recipients[0]).toMatchObject({ status: "bounced", enhanced: "5.1.10" });
  });

  test("loopback MX is refused by default", async () => {
    const dns = await startFakeDns({
      "evil.test": { MX: [[10, "mx.evil.test"]] },
      "mx.evil.test": { A: ["127.0.0.1"] },
    });
    cleanups.push(() => dns.stop());
    const report = await deliver(
      {
        domain: "evil.test",
        from: "a@bunzzle.com",
        recipients: ["x@evil.test"],
        data: MESSAGE,
        smtpUtf8: false,
      },
      {
        resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
        ehloName: "x",
      },
    );
    expect(report.sessions).toEqual([]);
    expect(report.recipients[0]?.status).toBe("bounced");
  });
});

describe("connection reuse", () => {
  const input = (
    port: number,
    pool: SessionPool,
    extra: Partial<SessionInput> = {},
  ): SessionInput => ({
    host: "mx.example.test",
    address: "127.0.0.1",
    port,
    ehloName: "out.bunzzle.test",
    policy: { rule: "opportunistic", required: false },
    from: "a@bunzzle.com",
    recipients: ["b@example.test"],
    data: MESSAGE,
    smtpUtf8: false,
    tlsCa: TEST_CA,
    timeouts: { greeting: 1000, quit: 200 },
    pool,
    perConnection: 100,
    ...extra,
  });

  test("several emails share one TLS connection: EHLO and STARTTLS once", async () => {
    mx = startFakeMx({});
    const pool = new SessionPool();
    const results = [];
    for (let i = 0; i < 3; i++) results.push(await runSession(input(mx.port, pool)));
    expect(results.map((r) => [r.phase, r.reused ?? false])).toEqual([
      ["done", false],
      ["done", true],
      ["done", true],
    ]);
    expect(results[2]?.tls.status).toBe("verified");
    expect(mx.sessions).toHaveLength(1);
    expect(mx.sessions[0]?.messages).toHaveLength(3);
    expect(mx.sessions[0]?.commands.filter((c) => c === "STARTTLS")).toHaveLength(1);
    await pool.closeAll();
    expect(commandsOf().at(-1)).toBe("QUIT");
  });

  test("the per-connection limit opens a new connection", async () => {
    mx = startFakeMx({});
    const pool = new SessionPool();
    for (let i = 0; i < 5; i++) await runSession(input(mx.port, pool, { perConnection: 2 }));
    expect(mx.sessions.map((s) => s.messages.length)).toEqual([2, 2, 1]);
    await pool.closeAll();
  });

  test("a server that closed the idle connection: retried on a fresh one, never twice", async () => {
    mx = startFakeMx({ closeAfterMessage: true });
    const pool = new SessionPool();
    const first = await runSession(input(mx.port, pool));
    await Bun.sleep(80);
    const second = await runSession(input(mx.port, pool));
    expect([first.phase, second.phase, second.reused ?? false]).toEqual(["done", "done", false]);
    expect(mx.sessions.flatMap((s) => s.messages)).toHaveLength(2);
    await pool.closeAll();
  });

  test("idle connections are capped across all destinations, oldest closed first", async () => {
    mx = startFakeMx({});
    const pool = new SessionPool({ maxIdle: 2 });
    for (const host of ["mx1.example.test", "mx2.example.test", "mx3.example.test"]) {
      await runSession(input(mx.port, pool, { host }));
    }
    expect([pool.size, pool.keys]).toEqual([2, 2]);
    await Bun.sleep(50);
    expect(mx.sessions[0]?.commands.at(-1)).toBe("QUIT");
    const again = await runSession(input(mx.port, pool, { host: "mx3.example.test" }));
    expect(again.reused).toBe(true);
    await pool.closeAll();
  });

  test("an idle connection times out and its destination is forgotten", async () => {
    mx = startFakeMx({});
    const pool = new SessionPool({ idleMs: 30 });
    await runSession(input(mx.port, pool));
    expect([pool.size, pool.keys]).toEqual([1, 1]);
    await Bun.sleep(120);
    expect([pool.size, pool.keys]).toEqual([0, 0]);
    expect(mx.sessions[0]?.commands.at(-1)).toBe("QUIT");
  });

  test("a connection whose transaction failed is not reused", async () => {
    mx = startFakeMx({ rcpt: () => "550 5.1.1 User unknown\r\n" });
    const pool = new SessionPool();
    await runSession(input(mx.port, pool));
    expect(pool.size).toBe(0);
    await runSession(input(mx.port, pool));
    expect(mx.sessions).toHaveLength(2);
  });
});
