import { afterAll, describe, expect, test } from "bun:test";
import { DerError, fromPem, notAfter, spkiOf } from "../../src/asn1/der.ts";
import {
  type DnsMessage,
  DnsWireError,
  decodeMessage,
  encodeQuery,
  nameToWire,
  type ResourceRecord,
  RRType,
  type TlsaData,
} from "../../src/dns/wire.ts";
import { Validator } from "../../src/dnssec/validator.ts";
import { NsServer } from "../../src/ns/server.ts";
import type { ZoneWire } from "../../src/ns/zone.ts";
import { matches, verifyDane } from "../../src/smtp/dane.ts";
import { startSmtpServer } from "../../src/smtpd/server.ts";
import { prepareSubmitted, SubmitError } from "../../src/submission/prepare.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { a } from "../support/dnssec.ts";
import { type TestWorld, world } from "../support/dnssec-world.ts";
import { fuzz, int, pick, report } from "./engine.ts";

const LONG = { timeout: 30 * 60_000 };
const TLS_DIR = `${import.meta.dir}/../fixtures/tls`;
const TLS = {
  cert: await Bun.file(`${TLS_DIR}/mx.pem`).text(),
  key: await Bun.file(`${TLS_DIR}/mx.key`).text(),
};
const latin1 = new TextDecoder("latin1");
const cleanups: (() => void)[] = [];
afterAll(() => {
  for (const c of cleanups) c();
});

function u16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}

function encodeRecord(r: ResourceRecord): number[] {
  const ttl = r.ttl >>> 0;
  return [
    ...nameToWire(r.name),
    ...u16(r.rrtype),
    ...u16(1),
    ttl >>> 24,
    (ttl >> 16) & 0xff,
    (ttl >> 8) & 0xff,
    ttl & 0xff,
    ...u16(r.rdata.length),
    ...r.rdata,
  ];
}

function encodeMessage(m: DnsMessage): Uint8Array {
  const additional = m.additional ?? [];
  const flags = 0x8000 | (m.authoritative ? 0x0400 : 0) | (m.truncated ? 0x0200 : 0) | m.rcode;
  return Uint8Array.from([
    ...u16(m.id),
    ...u16(flags | (m.authenticated ? 0x20 : 0)),
    ...u16(m.question ? 1 : 0),
    ...u16(m.answers.length),
    ...u16(m.authority.length),
    ...u16(additional.length),
    ...(m.question ? [...nameToWire(m.question.name), ...u16(m.question.type), ...u16(1)] : []),
    ...[...m.answers, ...m.authority, ...additional].flatMap(encodeRecord),
  ]);
}

interface Exchange {
  w: TestWorld;
  ask: [string, number];
  name: string;
  type: number;
}

async function exchanges(w: TestWorld, ask: [string, number]): Promise<[Exchange, Uint8Array][]> {
  const seen: [Exchange, Uint8Array][] = [];
  const fetch = async (name: string, type: number) => {
    const m = await w.fetch(name, type);
    seen.push([{ w, ask, name, type }, encodeMessage(m)]);
    return m;
  };
  const r = await new Validator({ fetch, anchors: w.anchors }).validate(...ask);
  expect(r.status).not.toBe("bogus");
  return seen;
}

async function send(port: number, input: Uint8Array, tls = false, wait = 15): Promise<string> {
  let received = "";
  const closed = Promise.withResolvers<void>();
  const ready = Promise.withResolvers<void>();
  const socket = await Bun.connect({
    hostname: "127.0.0.1",
    port,
    ...(tls ? { tls: { rejectUnauthorized: false } } : {}),
    socket: {
      handshake: () => ready.resolve(),
      data: (_s, chunk) => {
        received += new TextDecoder().decode(chunk);
      },
      close: () => {
        ready.resolve();
        closed.resolve();
      },
      error: () => {
        ready.resolve();
        closed.resolve();
      },
    },
  });
  if (tls) await Promise.race([ready.promise, Bun.sleep(1_000)]);
  expect(socket.write(input)).toBe(input.length);
  await Bun.sleep(wait);
  socket.end();
  await Promise.race([closed.promise, Bun.sleep(100)]);
  socket.terminate();
  return received;
}

describe("fuzz: certificates, DNSSEC, DNS server and submission", () => {
  test(
    "X.509 certificates and DANE matching",
    async () => {
      const certs = (
        await Promise.all(
          ["mx.pem", "ca.pem", "sts.pem", "sts-ca.pem"].map((f) =>
            Bun.file(`${TLS_DIR}/${f}`).text(),
          ),
        )
      ).flatMap(fromPem);
      const leaf = certs[0] as Uint8Array;
      const findings = await fuzz({
        seeds: certs,
        dictionary: [
          "\x30\x82",
          "\x30\x81\xff",
          "\x06\x09\x2a\x86\x48",
          "\x03\x01\x00",
          "\x17\x0d",
        ],
        maxLength: 8 * 1024,
        iterations: 2,
        expected: (e) => e instanceof DerError,
        async run(input, r) {
          const cert = parseCertificate(input);
          expect(cert).toBeDefined();
          spkiOf(input);
          notAfter(input);
          const record: TlsaData = {
            usage: pick(r, [2, 3]),
            selector: int(r, 2),
            matching: int(r, 3),
            data: pick(r, [new Uint8Array(32), input.subarray(0, 64)]),
          };
          matches(record, input);
          const verdict = await verifyDane([record], [input, leaf], ["mx.test"]);
          expect(typeof verdict.ok).toBe("boolean");
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "DNSSEC validation of tampered answers",
    async () => {
      const signed = await world(
        [[""], ["test"], ["example.test"]],
        [a("www.example.test", "192.0.2.1")],
      );
      const z = { denial: "nsec3" as const };
      const denied = await world(
        [
          ["", z],
          ["test", z],
          ["example.test", z],
        ],
        [],
      );
      const all = [
        ...(await exchanges(signed, ["www.example.test", RRType.A])),
        ...(await exchanges(denied, ["nothing.example.test", RRType.A])),
      ];
      const findings = await fuzz({
        seeds: all.map(([, wire], k) => Uint8Array.from([k, ...wire])),
        dictionary: [
          "\x00\x2e",
          "\x00\x30",
          "\x00\x2b",
          "\x00\x32",
          "\xc0\x0c",
          "\xff\xff\xff\xff",
        ],
        maxLength: 8 * 1024,
        iterations: 0.3,
        expected: (e) => e instanceof DnsWireError,
        async run(input) {
          const [ex] = all[(input[0] ?? 0) % all.length] as [Exchange, Uint8Array];
          const tampered = decodeMessage(input.subarray(1));
          const fetch = async (name: string, type: number) =>
            name === ex.name && type === ex.type ? tampered : ex.w.fetch(name, type);
          const r = await new Validator({ fetch, anchors: ex.w.anchors }).validate(...ex.ask);
          expect(["secure", "insecure", "bogus"]).toContain(r.status);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "authoritative DNS server queries",
    async () => {
      const apex = "dz.mail.test";
      const wire: ZoneWire = {
        serial: 7,
        records: [
          { name: `k3j9.${apex}`, type: "MX", ttl: 300, value: "mx.mail.test", priority: 10 },
          { name: `k3j9.${apex}`, type: "TXT", ttl: 300, value: "v=spf1 -all" },
          { name: `_check.${apex}`, type: "A", ttl: 300, value: "192.0.2.1" },
        ],
      };
      const server = new NsServer({ apex, names: ["ns1.mail.test", "ns2.mail.test"] });
      server.load(wire);
      const port = await server.listen("127.0.0.1", 0);
      cleanups.push(() => server.stop());
      const queries = [
        encodeQuery(1, `k3j9.${apex}`, RRType.MX),
        encodeQuery(2, `_check.${apex}`, RRType.A, true),
        encodeQuery(3, apex, RRType.SOA),
        encodeQuery(4, `nope.${apex}`, RRType.TXT),
      ];
      const findings = await fuzz({
        seeds: queries,
        dictionary: ["\xc0\x0c", "\x00\x29\x10\x00", "\x00\xff", "\x3f", "\x00\x00\x29"],
        maxLength: 1024,
        iterations: 3,
        run(input, r) {
          const reply =
            r() < 0.5 ? server.answerUdp(input, `192.0.2.${int(r, 255)}`) : server.answerTcp(input);
          if (reply) decodeMessage(reply);
        },
      });
      expect(report(findings)).toBe("");
      const framed = await fuzz({
        seeds: queries.map((q) => Uint8Array.from([...u16(q.length), ...q])),
        dictionary: ["\x00\x00", "\xff\xff", "\x00\x0c"],
        maxLength: 2048,
        iterations: 0.05,
        async run(input) {
          await send(port, input);
        },
      });
      expect(report(framed)).toBe("");
      const ok = server.answerTcp(queries[0] as Uint8Array);
      expect(ok && decodeMessage(ok).answers.length).toBeGreaterThan(0);
    },
    LONG,
  );

  test(
    "submitted messages and SMTP AUTH",
    async () => {
      const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");
      const now = new Date(Date.UTC(2026, 9, 19, 12, 0, 0));
      const messages = await fuzz({
        seeds: [
          crlf(
            'From: =?UTF-8?Q?Ay=C5=9Fe?= <Ayse@Acme.test>\nTo: a@x.test, "B" <b@x.test>\nBcc: h@x.test\nX-Bunzzle-Ref: f\nSubject: hi\n\nbody\n',
          ),
          crlf("From: a@acme.test\nMessage-ID: <k@acme.test>\nDate: x\n\nb\n"),
        ],
        dictionary: [
          "\r\n",
          "From: ",
          "Bcc: ",
          "Message-ID: <",
          "=?UTF-8?B?",
          "\r\n ",
          ",",
          "<",
          ">",
        ],
        maxLength: 16 * 1024,
        iterations: 2,
        expected: (e) => e instanceof SubmitError,
        run(input) {
          const r = prepareSubmitted(latin1.decode(input), ["u@x.test", "h@x.test"], now);
          const head = r.data.slice(0, r.data.indexOf("\r\n\r\n") + 2);
          expect(head).not.toMatch(/^(Bcc|X-Bunzzle-Ref|Return-Path|DKIM-Signature)[ \t]*:/im);
        },
      });
      expect(report(messages)).toBe("");

      let logins = 0;
      const smtp = startSmtpServer({
        hostname: "127.0.0.1",
        port: 0,
        name: "submit.test",
        banner: "submit.test ESMTP",
        tls: TLS,
        implicitTls: true,
        requireAuth: true,
        maxSize: 4096,
        blocking: null,
        authFailures: { max: 1_000_000, windowMs: 1 },
        hooks: {
          auth: async (password) => {
            if (password !== "secret") return null;
            logins++;
            return { id: "k" };
          },
          recipient: async () => null,
          message: async () => ({ code: 250, text: "2.0.0 ok" }),
        },
      });
      cleanups.push(() => smtp.stop());
      const b64 = (s: string) => new TextEncoder().encode(s).toBase64();
      const session = (lines: string[]) => `${lines.join("\r\n")}\r\n`;
      const auth = await fuzz({
        seeds: [
          session(["EHLO a", `AUTH PLAIN ${b64("\0u\0secret")}`, "MAIL FROM:<a@x.test>", "QUIT"]),
          session(["EHLO a", "AUTH LOGIN", b64("u"), b64("secret"), "NOOP"]),
          session(["EHLO a", "AUTH PLAIN", b64("\0u\0bad"), "AUTH PLAIN =", "*", "AUTH X"]),
        ],
        dictionary: ["AUTH PLAIN ", "AUTH LOGIN\r\n", "=", "*\r\n", "\0", "\r\n", "AGFAYg=="],
        maxLength: 4 * 1024,
        iterations: 0.03,
        async run(input) {
          await send(smtp.port, input, true, 30);
        },
      });
      expect(report(auth)).toBe("");
      expect(logins).toBeGreaterThan(0);
      const after = await send(
        smtp.port,
        new TextEncoder().encode("EHLO still.alive\r\n"),
        true,
        500,
      );
      expect(after).toContain("AUTH PLAIN LOGIN");
    },
    LONG,
  );
});
