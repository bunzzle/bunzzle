import { afterAll, describe, expect, test } from "bun:test";
import { z } from "zod";
import { createLogger } from "../../src/core/log.ts";
import { startApp } from "../../src/http/app.ts";
import { startInboundServer } from "../../src/inbound/server.ts";
import { method, RpcClient, serveRpc } from "../../src/ipc/rpc.ts";
import { SmtpConnection, SmtpError } from "../../src/smtp/connection.ts";
import { fuzz, int, pick, report } from "./engine.ts";

const errors: string[] = [];
const log = createLogger("error", {}, (line) => errors.push(line));
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-fuzz-${crypto.randomUUID()}`;
await Bun.$`mkdir -p ${dir}`.quiet();
const cleanups: (() => void)[] = [];
const LONG = { timeout: 30 * 60_000 };
const TLS_DIR = `${import.meta.dir}/../fixtures/tls`;
const TLS = {
  cert: await Bun.file(`${TLS_DIR}/mx.pem`).text(),
  key: await Bun.file(`${TLS_DIR}/mx.key`).text(),
};
afterAll(async () => {
  for (const c of cleanups) c();
  await Bun.$`rm -rf ${dir}`.quiet();
});

async function send(port: number, input: Uint8Array): Promise<string> {
  let received = "";
  const { promise, resolve } = Promise.withResolvers<void>();
  const socket = await Bun.connect({
    hostname: "127.0.0.1",
    port,
    socket: {
      data: (_s, chunk) => {
        received += new TextDecoder().decode(chunk);
      },
      close: () => resolve(),
      error: () => resolve(),
    },
  });
  socket.write(input);
  await Bun.sleep(15);
  socket.end();
  await Promise.race([promise, Bun.sleep(100)]);
  socket.terminate();
  return received;
}

describe("fuzz: network input", () => {
  test(
    "SMTP replies from a hostile server",
    async () => {
      let next: Uint8Array = new Uint8Array();
      const server = Bun.listen({
        hostname: "127.0.0.1",
        port: 0,
        socket: {
          open(s) {
            s.write(next);
            s.end();
          },
          data() {},
        },
      });
      cleanups.push(() => server.stop(true));
      const findings = await fuzz({
        seeds: [
          "220 mx.example.com ESMTP ready\r\n",
          "250-mx.example.com\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250-STARTTLS\r\n250 SMTPUTF8\r\n",
          "550-5.1.1 The email account that you tried to reach does not exist.\r\n550 5.1.1 https://support.example/answer\r\n",
          "421 4.7.0 Try again later, closing connection.\r\n",
          "354 Go ahead\r\n",
        ],
        dictionary: ["\r\n", "250-", "250 ", "5.7.1 ", "\n", "-", "  "],
        maxLength: 16 * 1024,
        iterations: 0.3,
        expected: (e) => e instanceof SmtpError,
        async run(input) {
          next = input;
          const conn = await SmtpConnection.connect({
            host: "127.0.0.1",
            port: server.port,
            timeoutMs: 1_000,
          });
          try {
            for (let i = 0; i < 300; i++) {
              const r = await conn.readReply(500);
              expect(r.code).toBeGreaterThanOrEqual(200);
              expect(r.code).toBeLessThan(600);
              expect(r.lines.length).toBeLessThanOrEqual(200);
            }
          } finally {
            conn.close();
          }
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "inbound SMTP listener",
    async () => {
      const accepted: { rcpts: string[]; size: number }[] = [];
      const inbound = startInboundServer({
        hostname: "127.0.0.1",
        port: 0,
        name: "mx.test",
        maxSize: 4096,
        tls: TLS,
        handlers: {
          recipient: async (a) => a.startsWith("b-") || a.startsWith("fbl@"),
          message: async (rcpts, raw) => {
            accepted.push({ rcpts, size: raw.length });
            return pick(Math.random, ["ok", "retry", "reject"] as const);
          },
        },
      });
      cleanups.push(() => inbound.stop());
      const session = (lines: string[]) => `${lines.join("\r\n")}\r\n`;
      const findings = await fuzz({
        seeds: [
          session([
            "EHLO a.test",
            "MAIL FROM:<>",
            "RCPT TO:<b-token@bounce.example.com>",
            "DATA",
            "Subject: x",
            "",
            "..dot",
            ".",
            "QUIT",
          ]),
          session([
            "HELO a",
            "MAIL FROM:<x@y>",
            "RCPT TO:<fbl@bounce.example.com>",
            "RSET",
            "NOOP",
          ]),
          session(["EHLO a", "DATA", "VRFY root", "BDAT 10 LAST", "STARTTLS"]),
        ],
        dictionary: [
          "\r\n",
          "\n",
          "\r",
          ".\r\n",
          "MAIL FROM:<",
          "RCPT TO:<b-",
          ">",
          "DATA\r\n",
          "\0",
        ],
        maxLength: 16 * 1024,
        iterations: 0.3,
        async run(input) {
          await send(inbound.port, input);
        },
      });
      expect(report(findings)).toBe("");
      for (const a of accepted) {
        expect(a.rcpts.length).toBeGreaterThan(0);
        expect(a.rcpts.length).toBeLessThanOrEqual(10);
        expect(a.size).toBeLessThanOrEqual(4096 + 2);
      }
      const after = await send(inbound.port, new TextEncoder().encode("EHLO still.alive\r\n"));
      expect(after).toContain("250");
    },
    LONG,
  );

  test(
    "IPC frames",
    async () => {
      const path = `${dir}/fuzz.sock`;
      const server = await serveRpc(path, {
        add: method(z.object({ a: z.number(), b: z.number() }), ({ a, b }) => a + b),
        echo: method(z.object({ text: z.string().max(100) }), ({ text }) => ({ text })),
      });
      cleanups.push(() => server.stop());
      const findings = await fuzz({
        seeds: [
          '{"id":1,"method":"add","params":{"a":1,"b":2}}\n',
          '{"id":2,"method":"echo","params":{"text":"hi"}}\n{"id":3,"method":"nope","params":null}\n',
          '{"id":1.5,"method":"add"}\n[]\nnull\n"x"\n',
        ],
        dictionary: ['"id":', '"method":', '"params":', "\n", "{", "}", "__proto__", "constructor"],
        maxLength: 8 * 1024,
        iterations: 0.3,
        async run(input) {
          const socket = await Bun.connect({
            unix: path,
            socket: { data() {}, close() {}, error() {} },
          });
          socket.write(input);
          socket.end();
        },
      });
      expect(report(findings)).toBe("");
      const client = new RpcClient(path);
      expect(await client.call("add", { a: 2, b: 3 })).toBe(5);
      client.close();
    },
    LONG,
  );

  test(
    "HTTP API",
    async () => {
      const lists = new Set(["listDomains", "listWebhooks", "listSuppressions", "ips", "paths"]);
      const core = {
        async call(m: string, _p: unknown, opts?: { result?: z.ZodType }) {
          const value =
            m === "authenticate"
              ? { id: "key", scope: "full", domains: null, rateLimit: 1_000_000 }
              : m === "health"
                ? { ok: true }
                : lists.has(m)
                  ? []
                  : { id: "0199f3a4-7c1e-7d55-9a21-3b6f0c9e4d12" };
          return opts?.result ? opts.result.parse(value) : value;
        },
      } as unknown as RpcClient;
      const app = startApp({ core, log, hostname: "127.0.0.1", port: 0 });
      cleanups.push(() => app.stop(true));
      const paths = [
        "/emails",
        "/emails/0199f3a4-7c1e-7d55-9a21-3b6f0c9e4d12",
        "/domains",
        "/domains/example.com",
        "/domains/example.com/verify",
        "/domains/example.com/rotate",
        "/webhooks",
        "/webhooks/x",
        "/suppressions",
        "/suppressions/a%40b.c",
        "/u/bae2kmxj4wl5wq3ru6gkfyzcjauwrwfqgbydiyc7zt",
        "/holds",
        "/holds/1",
        "/ips",
        "/paths",
        "/doctor",
        "/health",
        "/%00",
        "/emails/..%2f..%2fetc",
      ];
      const findings = await fuzz({
        seeds: [
          JSON.stringify({ from: "a@example.com", to: ["b@example.org"], subject: "s", text: "t" }),
          JSON.stringify({ name: "example.com" }),
          JSON.stringify({ url: "https://hooks.example.com/x", events: ["email.bounced"] }),
          JSON.stringify({ email: "a@b.c", scope: "bulk" }),
        ],
        dictionary: ['"', "{", "}", "[", "]", "null", "1e999", "\\u0000", " "],
        maxLength: 32 * 1024,
        iterations: 0.3,
        async run(input, r) {
          const path = pick(r, paths);
          const methodName = pick(r, ["GET", "POST", "DELETE", "PUT", "PATCH"]);
          const auth = pick(r, [
            `Bearer bz_${"a".repeat(43)}`,
            "Bearer x",
            "",
            `bearer   bz_${"_".repeat(43)}`,
          ]);
          const headers: Record<string, string> = { "content-type": "application/json" };
          if (auth) headers["authorization"] = auth;
          if (r() < 0.3) headers["idempotency-key"] = "k".repeat(int(r, 400));
          const res = await fetch(`http://127.0.0.1:${app.port}${path}`, {
            method: methodName,
            headers,
            ...(methodName === "GET" ? {} : { body: input }),
          });
          await res.arrayBuffer();
          if (res.status >= 500) throw new Error(`${methodName} ${path} → ${res.status}`);
        },
      });
      expect(report(findings)).toBe("");
      expect(errors).toEqual([]);
    },
    LONG,
  );
});
