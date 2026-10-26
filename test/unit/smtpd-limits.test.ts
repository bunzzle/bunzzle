import { afterEach, describe, expect, test } from "bun:test";
import { type SmtpServerOptions, startSmtpServer } from "../../src/smtpd/server.ts";

const stops: (() => void)[] = [];
afterEach(() => {
  for (const s of stops.splice(0)) s();
});

function server(extra: Partial<SmtpServerOptions>, messages: string[] = []) {
  const srv = startSmtpServer({
    hostname: "127.0.0.1",
    port: 0,
    name: "t.test",
    banner: "test",
    blocking: null,
    hooks: {
      recipient: async () => null,
      message: async (_r, raw) => {
        messages.push(raw);
        return { code: 250, text: "2.0.0 ok" };
      },
    },
    ...extra,
  });
  stops.push(() => srv.stop());
  return srv.port;
}

async function open(port: number) {
  let text = "";
  let closed = false;
  const socket = await Bun.connect({
    hostname: "127.0.0.1",
    port,
    socket: {
      data: (_s, chunk) => {
        text += new TextDecoder().decode(chunk);
      },
      close: () => {
        closed = true;
      },
    },
  });
  const wait = async (re: RegExp) => {
    for (let i = 0; i < 400 && !re.test(text) && !closed; i++) await Bun.sleep(5);
    return text;
  };
  return {
    socket,
    wait,
    say: async (line: string, re = /\r\n$/) => {
      text = "";
      socket.write(`${line}\r\n`);
      return wait(re);
    },
    closed: () => closed,
  };
}

const pause = { ms: 100, skip: () => false };

describe("early talker", () => {
  test("a client that talks before the greeting is refused", async () => {
    const c = await open(server({ greetPause: pause }));
    c.socket.write("EHLO x\r\n");
    const text = await c.wait(/^554 /m);
    expect(text).toStartWith("554 5.5.1");
    expect(text).not.toContain("220");
    await c.wait(/never/);
    expect(c.closed()).toBe(true);
  });

  test("a client that waits gets the greeting after the pause", async () => {
    const start = Date.now();
    const c = await open(server({ greetPause: pause }));
    expect(await c.wait(/^220 /m)).toStartWith("220 t.test");
    expect(Date.now() - start).toBeGreaterThanOrEqual(90);
    c.socket.end();
  });

  test("a skipped address gets the greeting at once", async () => {
    const start = Date.now();
    const c = await open(server({ greetPause: { ms: 2_000, skip: () => true } }));
    await c.wait(/^220 /m);
    expect(Date.now() - start).toBeLessThan(1_000);
    c.socket.end();
  });

  test("a client that sends the message before the 354 is refused", async () => {
    const messages: string[] = [];
    const c = await open(server({ greetPause: pause }, messages));
    await c.wait(/^220 /m);
    await c.say("EHLO x", /^250 /m);
    await c.say("MAIL FROM:<a@b.test>", /^250 /m);
    await c.say("RCPT TO:<c@t.test>", /^250 /m);
    expect(await c.say("DATA\r\nSubject: x\r\n\r\nb\r\n.", /^\d{3} /m)).toStartWith("554 5.5.1");
    await c.wait(/never/);
    expect(c.closed()).toBe(true);
    expect(messages).toHaveLength(0);
  });

  test("a client that waits for the 354 delivers", async () => {
    const messages: string[] = [];
    const c = await open(server({ greetPause: pause }, messages));
    await c.wait(/^220 /m);
    await c.say("EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@t.test>", /^250 2\.1\.5/m);
    expect(await c.say("DATA", /^354 /m)).toContain("354");
    expect(await c.say("Subject: x\r\n\r\nb\r\n.", /^250 /m)).toContain("250 2.0.0 ok");
    expect(messages).toEqual(["Subject: x\r\n\r\nb\r\n"]);
    c.socket.end();
  });
});

describe("per-IP rates", () => {
  const rates = { windowMs: 60_000, connections: 0, recipients: 0, nullSenderRecipients: 0 };

  test("connections over the limit get 421", async () => {
    const port = server({ rates: { ...rates, connections: 2 } });
    for (let i = 0; i < 2; i++) {
      const c = await open(port);
      expect(await c.wait(/^220 /m)).toStartWith("220");
      c.socket.end();
    }
    const c = await open(port);
    expect(await c.wait(/^421 /m)).toStartWith("421 4.7.0");
  });

  test("recipients over the limit get 450", async () => {
    const c = await open(server({ rates: { ...rates, recipients: 2 } }));
    await c.wait(/^220 /m);
    await c.say("EHLO x\r\nMAIL FROM:<a@b.test>", /^250 2\.1\.0/m);
    expect(await c.say("RCPT TO:<1@t.test>")).toStartWith("250");
    expect(await c.say("RCPT TO:<2@t.test>")).toStartWith("250");
    expect(await c.say("RCPT TO:<3@t.test>")).toStartWith("450 4.7.1");
    c.socket.end();
  });

  test("null-sender recipients have their own limit", async () => {
    const c = await open(server({ rates: { ...rates, nullSenderRecipients: 1 } }));
    await c.wait(/^220 /m);
    await c.say("EHLO x\r\nMAIL FROM:<>", /^250 2\.1\.0/m);
    expect(await c.say("RCPT TO:<1@t.test>")).toStartWith("250");
    expect(await c.say("RCPT TO:<2@t.test>")).toStartWith("450 4.7.1");
    await c.say("RSET");
    await c.say("MAIL FROM:<a@b.test>");
    expect(await c.say("RCPT TO:<3@t.test>")).toStartWith("250");
    c.socket.end();
  });
});
