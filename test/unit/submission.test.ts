import { describe, expect, test } from "bun:test";
import { toBinary } from "../../src/mime/parse.ts";
import { startSmtpServer } from "../../src/smtpd/server.ts";
import { prepareSubmitted, SubmitError } from "../../src/submission/prepare.ts";
import { smtpTalk } from "../support/smtp-client.ts";

const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");
const NOW = new Date(Date.UTC(2026, 9, 19, 12, 0, 0));

describe("prepareSubmitted", () => {
  test("drops Bcc and our own headers, adds Message-ID and Date, fills the meta", () => {
    const raw = crlf(`From: =?UTF-8?Q?Ay=C5=9Fe?= <Ayse@Acme.test>
To: a@x.test, "B" <b@x.test>
Cc: c@x.test
Bcc: hidden@x.test
X-Bunzzle-Ref: forged
Subject: hi

body
`);
    const r = prepareSubmitted(raw, ["a@x.test", "b@x.test", "c@x.test", "hidden@x.test"], NOW);
    expect(r.from).toBe("Ayse@acme.test");
    expect(r.fromDomain).toBe("acme.test");
    expect(r.data).not.toContain("Bcc:");
    expect(r.data).not.toContain("X-Bunzzle-Ref");
    expect(r.data).toMatch(/\r\nMessage-ID: <[^>]+@acme\.test>\r\n/);
    expect(r.data).toContain("Date: Mon, 19 Oct 2026 12:00:00 +0000");
    expect(r.data.endsWith("\r\n\r\nbody\r\n")).toBe(true);
    expect(r.meta).toMatchObject({
      from: "Ayşe <Ayse@Acme.test>",
      to: ["a@x.test", "b@x.test"],
      cc: ["c@x.test"],
      bcc: ["hidden@x.test"],
    });
  });

  test("keeps an existing Message-ID and Date", () => {
    const raw = crlf("From: a@acme.test\nMessage-ID: <keep@acme.test>\nDate: x\n\nb\n");
    const r = prepareSubmitted(raw, ["u@x.test"], NOW);
    expect(r.data.match(/Message-ID/g)?.length).toBe(1);
    expect(r.data).toContain("<keep@acme.test>");
  });

  test("UTF-8 8-bit content is accepted, other 8-bit content is refused", () => {
    const utf8 = toBinary(new TextEncoder().encode(crlf("From: a@acme.test\nSubject: ç\n\nçay\n")));
    expect(prepareSubmitted(utf8, ["u@x.test"], NOW).data).toContain("çay");
    const latin1 = `From: a@acme.test\r\n\r\n${String.fromCharCode(0xe7)}ay\r\n`;
    expect(() => prepareSubmitted(latin1, ["u@x.test"], NOW)).toThrow(SubmitError);
  });

  test("a message without exactly one valid From is refused", () => {
    for (const raw of [
      "Subject: x\r\n\r\nb\r\n",
      "From: a@acme.test\r\nFrom: b@acme.test\r\n\r\nb\r\n",
      "From: not an address\r\n\r\nb\r\n",
      "From: a@acme.test\r\nbroken header\r\n\r\nb\r\n",
      "From: a@acme.test\r\nSubject: s\nBcc: h@x.test\r\n\r\nb\r\n",
      "From: a@acme.test\r\nSubject: s\rX-Bunzzle-Ref: abc\r\n\r\nb\r\n",
    ]) {
      expect(() => prepareSubmitted(raw, ["u@x.test"], NOW)).toThrow(SubmitError);
    }
  });
});

describe("SMTP server engine", () => {
  test("too many failed logins lock the address out", async () => {
    const server = startSmtpServer({
      hostname: "127.0.0.1",
      port: 0,
      name: "t.test",
      banner: "test",
      implicitTls: true,
      tls: {
        cert: await Bun.file(`${import.meta.dir}/../fixtures/tls/mx.pem`).text(),
        key: await Bun.file(`${import.meta.dir}/../fixtures/tls/mx.key`).text(),
      },
      authFailures: { max: 2, windowMs: 60_000 },
      hooks: {
        auth: async () => null,
        recipient: async () => null,
        message: async () => ({ code: 250, text: "2.0.0 ok" }),
      },
    });
    const ca = await Bun.file(`${import.meta.dir}/../fixtures/tls/ca.pem`).text();
    const talk = async (lines: string[]) => {
      const out: string[] = [];
      let text = "";
      const done = Promise.withResolvers<void>();
      const s = await Bun.connect({
        hostname: "127.0.0.1",
        port: server.port,
        tls: { serverName: "mx.example.test", ca },
        socket: {
          data(sock, chunk) {
            text += new TextDecoder().decode(chunk);
            const replies = text.split("\r\n").filter((l) => /^\d{3} /.test(l));
            if (replies.length > out.length) {
              out.push(...replies.slice(out.length));
              const next = lines[out.length - 1];
              if (next === undefined) done.resolve();
              else sock.write(`${next}\r\n`);
            }
          },
          close() {
            done.resolve();
          },
        },
      });
      await done.promise;
      s.end();
      return out;
    };
    const bad = `AUTH PLAIN ${new TextEncoder().encode("\u0000u\u0000wrong").toBase64()}`;
    expect((await talk([bad, bad])).slice(1)).toEqual([
      "535 5.7.8 Authentication credentials invalid",
      "535 5.7.8 Authentication credentials invalid",
    ]);
    expect((await talk([]))[0]).toStartWith("421 4.7.0 Too many failed logins");
    server.stop();
  });

  test("an address that keeps guessing recipients or sending junk is shut out", async () => {
    const server = startSmtpServer({
      hostname: "127.0.0.1",
      port: 0,
      name: "t.test",
      banner: "test",
      blocking: { maxStrikes: 3, windowMs: 60_000, banMs: 60_000 },
      hooks: {
        recipient: async (a) => (a === "ok@t.test" ? null : { code: 550, text: "5.1.1 no" }),
        message: async () => ({ code: 250, text: "2.0.0 ok" }),
      },
    });
    const talk = async (lines: string[]) => {
      const out: string[] = [];
      let text = "";
      const done = Promise.withResolvers<void>();
      const s = await Bun.connect({
        hostname: "127.0.0.1",
        port: server.port,
        socket: {
          data(sock, chunk) {
            text += new TextDecoder().decode(chunk);
            const replies = text.split("\r\n").filter((l) => /^\d{3} /.test(l));
            if (replies.length > out.length) {
              out.push(...replies.slice(out.length));
              const next = lines[out.length - 1];
              if (next === undefined) done.resolve();
              else sock.write(`${next}\r\n`);
            }
          },
          close() {
            done.resolve();
          },
        },
      });
      await done.promise;
      s.end();
      return out;
    };
    const guesses = await talk([
      "EHLO x",
      "MAIL FROM:<a@b.test>",
      "RCPT TO:<ok@t.test>",
      "RCPT TO:<x1@t.test>",
      "BOGUS",
      "RCPT TO:<x2@t.test>",
      "RCPT TO:<x3@t.test>",
    ]);
    expect(guesses.at(-1)).toStartWith("421 4.7.0 Too many errors");
    expect(guesses.filter((r) => r.startsWith("550"))).toHaveLength(1);
    expect((await talk([]))[0]).toStartWith("421 4.7.0 Too many errors");
    server.stop();
  });

  test("bare CR and LF inside DATA become CRLF and never end the message", async () => {
    const raws: string[] = [];
    const server = startSmtpServer({
      hostname: "127.0.0.1",
      port: 0,
      name: "t.test",
      banner: "test",
      hooks: {
        recipient: async () => null,
        message: async (_r, raw) => {
          raws.push(raw);
          return { code: 250, text: "2.0.0 ok" };
        },
      },
    });
    const talk = await smtpTalk(server.port, [
      "EHLO x",
      "MAIL FROM:<a@b.test>",
      "RCPT TO:<ok@t.test>",
      "DATA",
      "Subject: s\r\n\r\na\nb\rc\r\nd\n.\r\n.e\r\r\n.",
      "QUIT",
    ]);
    server.stop();
    expect(talk.replies[5]).toStartWith("250");
    expect(raws).toEqual(["Subject: s\r\n\r\na\r\nb\r\nc\r\nd\r\n.\r\ne\r\n\r\n"]);
  });

  test("commands pipelined after the end of DATA start the next message", async () => {
    const got: [string[], string][] = [];
    const server = startSmtpServer({
      hostname: "127.0.0.1",
      port: 0,
      name: "t.test",
      banner: "test",
      hooks: {
        recipient: async () => null,
        message: async (rcpts, raw) => {
          got.push([rcpts, raw]);
          return { code: 250, text: "2.0.0 ok" };
        },
      },
    });
    let text = "";
    const socket = await Bun.connect({
      hostname: "127.0.0.1",
      port: server.port,
      socket: {
        data: (_s, chunk) => {
          text += new TextDecoder().decode(chunk);
        },
      },
    });
    const until = async (n: number) => {
      while ((text.match(/^354 /gm) ?? []).length < n) await Bun.sleep(5);
    };
    socket.write("EHLO x\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@t.test>\r\nDATA\r\n");
    await until(1);
    socket.write("x\r\n.\r\nMAIL FROM:<e@b.test>\r\nRCPT TO:<g@t.test>\r\nDATA\r\n");
    await until(2);
    socket.write("y\r\n.\r\nQUIT\r\n");
    while (!text.includes("221 ")) await Bun.sleep(5);
    socket.end();
    server.stop();
    expect(text).not.toContain("502");
    expect(got).toEqual([
      [["c@t.test"], "x\r\n"],
      [["g@t.test"], "y\r\n"],
    ]);
  });

  test("after STARTTLS the client must say EHLO again and the old name is gone", async () => {
    const dir = `${import.meta.dir}/../fixtures/tls`;
    const helos: (string | null)[] = [];
    const server = startSmtpServer({
      hostname: "127.0.0.1",
      port: 0,
      name: "t.test",
      banner: "test",
      tls: {
        cert: await Bun.file(`${dir}/mx.pem`).text(),
        key: await Bun.file(`${dir}/mx.key`).text(),
      },
      hooks: {
        sender: async (_a, session) => {
          helos.push(session.helo);
          return null;
        },
        recipient: async () => null,
        message: async () => ({ code: 250, text: "2.0.0 ok" }),
      },
    });
    let text = "";
    let wake = () => {};
    let upgraded = false;
    const read = (chunk: Uint8Array) => {
      text += new TextDecoder().decode(chunk);
      wake();
    };
    const next = async () => {
      for (;;) {
        const m = /^\d{3} .*\r\n/m.exec(text);
        if (m) {
          text = text.slice(m.index + m[0].length);
          return m[0].trim();
        }
        await new Promise<void>((r) => {
          wake = r;
          setTimeout(r, 2_000);
        });
      }
    };
    const plain = await Bun.connect({
      hostname: "127.0.0.1",
      port: server.port,
      socket: {
        data: (_s, chunk) => {
          if (!upgraded) read(chunk);
        },
      },
    });
    await next();
    plain.write("EHLO before.test\r\n");
    await next();
    plain.write("STARTTLS\r\n");
    expect(await next()).toStartWith("220");
    upgraded = true;
    const ready = Promise.withResolvers<void>();
    const [, secure] = plain.upgradeTLS({
      tls: { rejectUnauthorized: false },
      socket: { data: (_s, chunk) => read(chunk), handshake: () => ready.resolve() },
    });
    await ready.promise;
    const say = async (line: string) => {
      secure.write(`${line}\r\n`);
      return next();
    };
    expect(await say("MAIL FROM:<a@b.test>")).toStartWith("503 5.5.1");
    expect(await say("EHLO after.test")).toStartWith("250");
    expect(await say("MAIL FROM:<a@b.test>")).toStartWith("250");
    secure.end();
    server.stop();
    expect(helos).toEqual(["after.test"]);
  });
});
