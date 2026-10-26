import { afterEach, describe, expect, test } from "bun:test";
import { startInboundServer } from "../../src/inbound/server.ts";
import { SmtpConnection } from "../../src/smtp/connection.ts";
import { runSession } from "../../src/smtp/session.ts";
import { TEST_CA } from "../support/fake-mx.ts";

const TLS_DIR = `${import.meta.dir}/../fixtures/tls`;
const TLS = {
  cert: await Bun.file(`${TLS_DIR}/mx.pem`).text(),
  key: await Bun.file(`${TLS_DIR}/mx.key`).text(),
};
const BOUNCE = "b-token@bounce.example.test";

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const c of cleanups.splice(0)) c();
});

function start(tls: typeof TLS | null) {
  const received: { rcpts: string[]; raw: string }[] = [];
  const server = startInboundServer({
    hostname: "127.0.0.1",
    port: 0,
    name: "mx.example.test",
    tls,
    handlers: {
      recipient: async (a) => a.startsWith("b-"),
      message: async (rcpts, raw) => {
        received.push({ rcpts, raw });
        return "ok";
      },
    },
  });
  cleanups.push(() => server.stop());
  return { port: server.port, received };
}

async function connect(port: number) {
  const conn = await SmtpConnection.connect({ host: "127.0.0.1", port, timeoutMs: 2000 });
  cleanups.push(() => conn.close());
  await conn.readReply(2000);
  return conn;
}

async function ehlo(conn: SmtpConnection) {
  await conn.write("EHLO client.test\r\n", 2000);
  return (await conn.readReply(2000)).lines;
}

describe("inbound STARTTLS", () => {
  test("is offered only when a certificate is configured, and not again after the upgrade", async () => {
    const plain = await connect(start(null).port);
    expect(await ehlo(plain)).not.toContain("STARTTLS");
    await plain.write("STARTTLS\r\n", 2000);
    expect((await plain.readReply(2000)).code).toBe(502);

    const conn = await connect(start(TLS).port);
    expect(await ehlo(conn)).toContain("STARTTLS");
    await conn.write("STARTTLS\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(220);
    const info = await conn.startTls("mx.example.test", 2000, TEST_CA);
    expect(info.authorized).toBe(true);
    expect(info.version).toMatch(/TLSv1\.[23]/);
    expect(await ehlo(conn)).not.toContain("STARTTLS");
    await conn.write("STARTTLS\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(503);
  });

  test("REQUIRETLS is offered and accepted only over TLS", async () => {
    const { port, received } = start(TLS);
    const plain = await connect(port);
    expect(await ehlo(plain)).not.toContain("REQUIRETLS");
    await plain.write(`MAIL FROM:<x@sender.test> REQUIRETLS\r\n`, 2000);
    expect((await plain.readReply(2000)).code).toBe(530);

    const conn = await connect(port);
    await ehlo(conn);
    await conn.write("STARTTLS\r\n", 2000);
    await conn.readReply(2000);
    await conn.startTls("mx.example.test", 2000, TEST_CA);
    expect(await ehlo(conn)).toContain("REQUIRETLS");
    for (const line of [`MAIL FROM:<x@sender.test> REQUIRETLS`, `RCPT TO:<${BOUNCE}>`, "DATA"]) {
      await conn.write(`${line}\r\n`, 2000);
      expect((await conn.readReply(2000)).code).toBeLessThan(400);
    }
    await conn.write("Subject: x\r\n\r\nx\r\n.\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(250);
    expect(received).toHaveLength(1);
  });

  test("delivers a bounce over TLS with Bunzzle's own SMTP client", async () => {
    const { port, received } = start(TLS);
    const result = await runSession({
      host: "mx.example.test",
      address: "127.0.0.1",
      port,
      ehloName: "mx.remote.test",
      policy: { rule: "opportunistic", required: false },
      from: "",
      recipients: [BOUNCE],
      data: "Subject: Undelivered\r\n\r\nGone\r\n",
      smtpUtf8: false,
      tlsCa: TEST_CA,
      timeouts: { greeting: 2000, quit: 200 },
    });
    expect(result.tls.status).toBe("verified");
    expect(result.recipients[0]?.status).toBe("delivered");
    expect(received).toHaveLength(1);
    expect(received[0]?.rcpts).toEqual([BOUNCE]);
  });

  test("discards plaintext commands pipelined after STARTTLS", async () => {
    const { port, received } = start(TLS);
    const conn = await connect(port);
    await ehlo(conn);
    await conn.write(
      `STARTTLS\r\nMAIL FROM:<>\r\nRCPT TO:<${BOUNCE}>\r\nDATA\r\nSubject: injected\r\n\r\nx\r\n.\r\n`,
      2000,
    );
    expect((await conn.readReply(2000)).code).toBe(220);
    expect(conn.hasBufferedData()).toBe(false);
    await conn.startTls("mx.example.test", 2000, TEST_CA);
    await conn.write("MAIL FROM:<>\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(503);
    await ehlo(conn);
    await conn.write("MAIL FROM:<>\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(250);
    await conn.write("DATA\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(503);
    expect(received).toHaveLength(0);
  });

  test("rejects STARTTLS with parameters and keeps the session usable", async () => {
    const conn = await connect(start(TLS).port);
    await ehlo(conn);
    await conn.write("STARTTLS now\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(501);
    await conn.write("NOOP\r\n", 2000);
    expect((await conn.readReply(2000)).code).toBe(250);
  });
});
