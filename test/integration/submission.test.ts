import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { frame } from "../../src/milter/protocol.ts";
import { type Reply, SmtpConnection } from "../../src/smtp/connection.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { startFakeMilter } from "../support/fake-milter.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const TLS = `${import.meta.dir}/../fixtures/tls`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let key = "";
let readOnly = "";
let ca = "";
let deliveredId = "";

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  return { stdout, code };
}

async function newKey(scope: string): Promise<string> {
  const r = await cli("keys", "create", "--name", "smtp", "--scope", scope);
  return (r.stdout.trim().split("\n").at(-1) ?? "").trim();
}

const b64 = (s: string) => new TextEncoder().encode(s).toBase64();
const plain = (k: string) => b64(`\u0000bunzzle\u0000${k}`);

const show = (r: Reply) =>
  `${r.code} ${r.enhanced ? `${r.enhanced} ` : ""}${r.lines.join(" ")}`.trim();

async function session(port: number) {
  const c = await SmtpConnection.connect({ host: "127.0.0.1", port, timeoutMs: 5_000 });
  const say = async (line: string) => {
    await c.write(`${line}\r\n`, 5_000);
    return show(await c.readReply(5_000));
  };
  const banner = show(await c.readReply(5_000));
  return { c, say, banner };
}

beforeAll(async () => {
  ca = await Bun.file(`${TLS}/ca.pem`).text();
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_RETRY_SCALE: "0.001",
    BUNZZLE_SUBMISSION_HOST: "127.0.0.1",
    BUNZZLE_SUBMISSION_PORT: "0",
    BUNZZLE_SUBMISSION_TLS_PORT: "0",
    BUNZZLE_SUBMISSION_HOSTNAME: "mx.example.test",
    BUNZZLE_SUBMISSION_TLS_CERT_FILE: `${TLS}/mx.pem`,
    BUNZZLE_SUBMISSION_TLS_KEY_FILE: `${TLS}/mx.key`,
    BUNZZLE_EVENT_LOG: "true",
  });
  key = await newKey("send");
  readOnly = await newKey("read");
  await cli("domains", "add", "acme.test");
  const d = (await (
    await fetch(`${served.url}/domains/acme.test`, {
      headers: { authorization: `Bearer ${await newKey("full")}` },
    })
  ).json()) as { records: { record: string; name: string; value: string }[] };
  for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
  await cli("domains", "verify", "acme.test");
}, 30_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

describe("SMTP submission", () => {
  test("nothing secret before TLS: no AUTH offered, AUTH and MAIL refused", async () => {
    const [port] = served.submissionPorts;
    const { c, say, banner } = await session(port as number);
    expect(banner).toContain("ESMTP Bunzzle submission");
    const ehlo = await say("EHLO app.test");
    expect(ehlo).toContain("STARTTLS");
    expect(ehlo).not.toContain("AUTH");
    expect(ehlo).not.toContain("REQUIRETLS");
    expect(await say(`AUTH PLAIN ${plain(key)}`)).toStartWith("530 5.7.0");
    expect(await say("MAIL FROM:<hello@acme.test>")).toStartWith("530 5.7.0");
    c.close();
  });

  test("STARTTLS, login with an API key, and the email is delivered without its Bcc header", async () => {
    const [port] = served.submissionPorts;
    const { c, say } = await session(port as number);
    await say("EHLO app.test");
    expect(await say("STARTTLS")).toStartWith("220");
    const tls = await c.startTls("mx.example.test", 5_000, ca);
    expect(tls.authorized).toBe(true);
    expect(await say("EHLO app.test")).toContain("AUTH PLAIN LOGIN");
    expect(await say("MAIL FROM:<hello@acme.test>")).toStartWith("530 5.7.0 Authentication");
    expect(await say(`AUTH PLAIN ${plain(readOnly)}`)).toStartWith("535 5.7.8");
    expect(await say(`AUTH PLAIN ${plain(key)}`)).toStartWith("235");
    expect(await say("MAIL FROM:<hello@acme.test>")).toStartWith("250");
    expect(await say("RCPT TO:<user@example.test>")).toStartWith("250");
    expect(await say("RCPT TO:<hidden@example.test>")).toStartWith("250");
    expect(await say("DATA")).toStartWith("354");
    const before = mx.sessions.length;
    const accepted = await say(
      [
        "From: Acme <hello@acme.test>",
        "To: user@example.test",
        "Bcc: hidden@example.test",
        "Subject: Sent over SMTP",
        "",
        "Hello from a mailer.",
        ".",
      ].join("\r\n"),
    );
    expect(accepted).toMatch(/^250 2\.0\.0 Ok: queued as \S+/);
    const id = accepted.split(" ").at(-1) as string;
    let status = "";
    for (let i = 0; i < 100 && status !== "delivered"; i++) {
      const r = await fetch(`${served.url}/emails/${id}`, {
        headers: { authorization: `Bearer ${await newKey("read")}` },
      });
      status = ((await r.json()) as { last_event: string }).last_event;
      if (status !== "delivered") await Bun.sleep(100);
    }
    expect(status).toBe("delivered");
    deliveredId = id;
    const received = mx.sessions
      .slice(before)
      .flatMap((s) => s.messages)
      .join("\n");
    expect(received).toContain("Subject: Sent over SMTP");
    expect(received).toContain("Message-ID: <");
    expect(received).not.toContain("Bcc:");
    expect(await say("QUIT")).toStartWith("221");
  });

  test("REQUIRETLS on MAIL FROM travels with the email and is enforced", async () => {
    const [port] = served.submissionPorts;
    const { c, say } = await session(port as number);
    await say("EHLO app.test");
    await say("STARTTLS");
    await c.startTls("mx.example.test", 5_000, ca);
    expect(await say("EHLO app.test")).toContain("REQUIRETLS");
    expect(await say(`AUTH PLAIN ${plain(key)}`)).toStartWith("235");
    expect(await say("MAIL FROM:<hello@acme.test> REQUIRETLS")).toStartWith("250");
    expect(await say("RCPT TO:<user@example.test>")).toStartWith("250");
    expect(await say("DATA")).toStartWith("354");
    const accepted = await say(
      ["From: hello@acme.test", "To: user@example.test", "Subject: Secret", "", "x", "."].join(
        "\r\n",
      ),
    );
    const id = accepted.split(" ").at(-1) as string;
    let body: { last_event: string } = { last_event: "" };
    for (let i = 0; i < 100 && body.last_event !== "bounced"; i++) {
      const r = await fetch(`${served.url}/emails/${id}`, {
        headers: { authorization: `Bearer ${await newKey("read")}` },
      });
      body = (await r.json()) as { last_event: string };
      if (body.last_event !== "bounced") await Bun.sleep(100);
    }
    expect(body.last_event).toBe("bounced");
    expect(JSON.stringify(body)).toContain('"class":"requiretls-unsupported"');
    expect(JSON.stringify(body)).toContain('"suppression_candidate":false');
    expect(await say("QUIT")).toStartWith("221");
  });

  test("the event log has the email's events as JSON lines", async () => {
    const dir = `${served.dir}/logs/events`;
    const mine = async () => {
      const out: Record<string, unknown>[] = [];
      for (const name of new Bun.Glob("events-*.jsonl").scanSync({ cwd: dir })) {
        for (const line of (await Bun.file(`${dir}/${name}`).text()).split("\n").filter(Boolean)) {
          const e = JSON.parse(line) as Record<string, unknown>;
          if (e["email_id"] === deliveredId) out.push(e);
        }
      }
      return out;
    };
    let events = await mine();
    for (let i = 0; i < 50 && !events.some((e) => e["event"] === "recipient"); i++) {
      await Bun.sleep(100);
      events = await mine();
    }
    expect(events.map((e) => e["event"])).toContain("queued");
    expect(events.find((e) => e["event"] === "recipient")).toMatchObject({
      source: expect.any(String),
      data: { status: "delivered" },
    });
    expect((await Bun.file(dir).stat()).mode & 0o777).toBe(0o750);
  });

  test("a sender domain that is not verified, and a wrong key, are refused clearly", async () => {
    const [port] = served.submissionPorts;
    const { c, say } = await session(port as number);
    await say("EHLO app.test");
    await say("STARTTLS");
    await c.startTls("mx.example.test", 5_000, ca);
    await say("EHLO app.test");
    expect(await say("AUTH LOGIN")).toBe("334 VXNlcm5hbWU6");
    expect(await say(b64("anyone"))).toBe("334 UGFzc3dvcmQ6");
    expect(await say(b64(key))).toStartWith("235");
    await say("MAIL FROM:<x@other.test>");
    await say("RCPT TO:<user@example.test>");
    await say("DATA");
    const refused = await say(["From: x@other.test", "Subject: no", "", "x", "."].join("\r\n"));
    expect(refused).toMatch(/^550 5\.7\.1 .*other\.test/);
    c.close();
  });

  test("implicit TLS port offers AUTH right away", async () => {
    const port = served.submissionPorts[1] as number;
    let text = "";
    const got = Promise.withResolvers<void>();
    const socket = await Bun.connect({
      hostname: "127.0.0.1",
      port,
      tls: { serverName: "mx.example.test", ca },
      socket: {
        data(_s, chunk) {
          text += new TextDecoder().decode(chunk);
          if (/^250 /m.test(text)) got.resolve();
        },
        open(s) {
          s.write("EHLO app.test\r\n");
        },
      },
    });
    await got.promise;
    socket.end();
    expect(text).toContain("AUTH PLAIN LOGIN");
    expect(text).not.toContain("STARTTLS");
  });

  test("a content filter refusal is a 550, a filter asking to wait is a 451", async () => {
    const milter = startFakeMilter();
    const add = await cli("hooks", "add", "milter", `inet:127.0.0.1:${milter.port}`);
    try {
      const [port] = served.submissionPorts;
      const { c, say } = await session(port as number);
      await say("EHLO app.test");
      await say("STARTTLS");
      await c.startTls("mx.example.test", 5_000, ca);
      await say("EHLO app.test");
      expect(await say(`AUTH PLAIN ${plain(key)}`)).toStartWith("235");
      const attempt = async () => {
        await say("MAIL FROM:<hello@acme.test>");
        await say("RCPT TO:<user@example.test>");
        await say("DATA");
        return say(["From: hello@acme.test", "Subject: filtered", "", "x", "."].join("\r\n"));
      };
      milter.onEnd = () => [frame("y", "554 5.7.1 virus found\0")];
      expect(await attempt()).toMatch(/^550 5\.7\.1 .*virus found/);
      milter.onEnd = () => [frame("t")];
      expect(await attempt()).toStartWith("451 4.7.1");
      c.close();
    } finally {
      await cli("hooks", "remove", add.stdout.split(/\s+/)[1] as string);
      milter.stop();
    }
  });
});
