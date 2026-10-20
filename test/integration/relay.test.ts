import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { localTransport } from "../../src/delivery/transport.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import type { Relay } from "../../src/smtp/deliver.ts";
import { startSmtpServer } from "../../src/smtpd/server.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { TEST_CA } from "../support/fake-mx.ts";

const TLS = `${import.meta.dir}/../fixtures/tls`;
const CERT = await Bun.file(`${TLS}/mx.pem`).text();
const KEY = await Bun.file(`${TLS}/mx.key`).text();
let dns: FakeDns;
const received: { from: string; rcpts: string[]; user: unknown }[] = [];
const servers: { port: number; stop(): void }[] = [];

function relayServer(implicitTls: boolean) {
  const s = startSmtpServer({
    hostname: "127.0.0.1",
    port: 0,
    name: "mx.example.test",
    banner: "relay",
    tls: { cert: CERT, key: KEY },
    implicitTls,
    requireTls: true,
    requireAuth: true,
    blocking: null,
    hooks: {
      auth: async (password) => (password === "s3cret" ? { user: "app" } : null),
      sender: async () => null,
      recipient: async () => null,
      message: async (rcpts, _raw, session) => {
        received.push({ from: "", rcpts, user: session.user });
        return { code: 250, text: "2.0.0 relayed" };
      },
    },
  });
  servers.push(s);
  return s;
}

beforeAll(async () => {
  dns = await startFakeDns({ "mx.example.test": { A: ["127.0.0.1"] } });
});

afterAll(() => {
  for (const s of servers) s.stop();
  dns.stop();
});

async function send(relay: Relay, ca: string | null = TEST_CA) {
  const t = localTransport(
    {
      resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
      ehloName: "out.bunzzle.test",
      allowPrivate: true,
      ...(ca ? { tlsCa: ca } : {}),
      timeouts: { greeting: 2_000, quit: 200 },
      relay,
    },
    async () => ({ data: "From: a@bunzzle.test\r\nSubject: x\r\n\r\nx\r\n", bounceToken: "t" }),
  );
  return t.deliver({
    key: "k",
    recall: null,
    messageId: "m",
    domain: "gmail.example",
    destination: await t.lookup("gmail.example"),
    from: "a@bunzzle.test",
    recipients: ["someone@gmail.example"],
    smtpUtf8: false,
    requireTls: false,
    body: { epoch: 1, wrapped: new Uint8Array(), body: new Uint8Array() },
  });
}

describe("sending through a relay", () => {
  test("STARTTLS, a verified certificate and AUTH, then the relay takes the email", async () => {
    const s = relayServer(false);
    const before = received.length;
    const r = await send({
      host: "mx.example.test",
      port: s.port,
      implicitTls: false,
      username: "bunzzle",
      password: "s3cret",
    });
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.policy?.rule).toBe("relay");
    expect(r.sessions[0]?.tls.status).toBe("verified");
    expect(received.length).toBe(before + 1);
    expect(received.at(-1)?.rcpts).toEqual(["someone@gmail.example"]);
    const talk = (r.sessions[0]?.transcript ?? []).map(([, who, text]) => `${who} ${text}`);
    expect(talk).toContain("C AUTH PLAIN [hidden]");
    expect(talk.join("\n")).not.toContain(btoa("\0bunzzle\0s3cret"));
    expect(talk.join("\n")).not.toContain("s3cret");
  });

  test("TLS from the first byte works too", async () => {
    const s = relayServer(true);
    const r = await send({
      host: "mx.example.test",
      port: s.port,
      implicitTls: true,
      username: "bunzzle",
      password: "s3cret",
    });
    expect(r.recipients[0]?.status).toBe("delivered");
  });

  test("a wrong password or an untrusted certificate never sends", async () => {
    const s = relayServer(false);
    const wrong = await send({
      host: "mx.example.test",
      port: s.port,
      implicitTls: false,
      username: "bunzzle",
      password: "nope",
    });
    expect(wrong.recipients[0]?.status).toBe("deferred");
    expect(wrong.sessions[0]?.error).toContain("relay login failed");
    const untrusted = await send(
      {
        host: "mx.example.test",
        port: s.port,
        implicitTls: false,
        username: "bunzzle",
        password: "s3cret",
      },
      null,
    );
    expect(untrusted.recipients[0]?.status).toBe("deferred");
    expect(untrusted.recipients[0]?.enhanced).toBe("4.7.5");
  });
});
