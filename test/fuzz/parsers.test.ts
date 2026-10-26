import { describe, expect, test } from "bun:test";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { checkDkim } from "../../src/dkim/check.ts";
import { keyFromTxt, selectorsOf } from "../../src/dkim/verify.ts";
import { parseDmarcRecord } from "../../src/dmarc/policy.ts";
import type { DnsAnswer, QueryType, Resolver } from "../../src/dns/resolver.ts";
import { DnsWireError, decodeMessage, encodeQuery, RRType } from "../../src/dns/wire.ts";
import { ApiError } from "../../src/http/errors.ts";
import { prepareEmail, sendSchema } from "../../src/http/send.ts";
import { fromDomain } from "../../src/inbound/auth.ts";
import { classifyReport } from "../../src/inbound/parse.ts";
import {
  AddressError,
  normalizeAddress,
  parseAddress,
  parseAddressList,
} from "../../src/mime/address.ts";
import {
  decodeWords,
  MIME_LIMITS,
  MimeParseError,
  parseHeaderBlock,
  parseMime,
  parseParams,
  walkParts,
} from "../../src/mime/parse.ts";
import { classify, retryHint } from "../../src/replies/classify.ts";
import { makeToken, readToken, unbase32 } from "../../src/signer/tokens.ts";
import { mxAllowed, parsePolicy } from "../../src/smtp/mta-sts.ts";
import { checkSpf } from "../../src/spf/check.ts";
import { fuzz, int, pick, report } from "./engine.ts";

const latin1 = new TextDecoder("latin1");
const utf8 = new TextDecoder();
const LONG = { timeout: 30 * 60_000 };
const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");

function name(n: string): number[] {
  const out: number[] = [];
  for (const label of n.split(".")) {
    out.push(label.length, ...new TextEncoder().encode(label));
  }
  out.push(0);
  return out;
}

const u16 = (n: number) => [n >> 8, n & 0xff];
const u32 = (n: number) => [n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];

function rr(type: number, data: number[]): number[] {
  return [0xc0, 12, ...u16(type), ...u16(1), ...u32(300), ...u16(data.length), ...data];
}

function response(qname: string, qtype: number, answers: number[][], flags = 0x8180): Uint8Array {
  const q = encodeQuery(0x1234, qname, qtype);
  const head = [...u16(0x1234), ...u16(flags), ...u16(1), ...u16(answers.length), 0, 0, 0, 0];
  return Uint8Array.from([...head, ...q.subarray(12), ...answers.flat()]);
}

const txt = (s: string) => [s.length, ...new TextEncoder().encode(s)];

const DNS_SEEDS = [
  response("example.com", RRType.MX, [
    rr(RRType.MX, [0, 10, ...name("mx1.example.com")]),
    rr(RRType.MX, [0, 20, 0xc0, 12]),
  ]),
  response("mx1.example.com", RRType.A, [rr(RRType.A, [192, 0, 2, 1])]),
  response("mx1.example.com", RRType.AAAA, [rr(RRType.AAAA, Array(16).fill(1))]),
  response("example.com", RRType.TXT, [rr(RRType.TXT, [...txt("v=spf1 -all"), ...txt("x")])]),
  response("7.2.0.192.in-addr.arpa", RRType.PTR, [rr(RRType.PTR, name("mail.example.com"))]),
  response("www.example.com", RRType.A, [rr(RRType.CNAME, name("example.net"))]),
  response("nx.example.com", RRType.MX, [], 0x8183),
  response("t.example.com", RRType.TXT, [rr(RRType.TXT, txt("truncated"))], 0x8380),
];

const DSN = crlf(`From: MAILER-DAEMON@mx.example.test
Subject: Undelivered Mail Returned to Sender
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
	boundary="ABC"

--ABC
Content-Type: text/plain

Could not deliver.

--ABC
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.example.test

Final-Recipient: rfc822; nobody@example.test
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 5.1.1 <nobody@example.test>: Recipient address
 rejected: User unknown

--ABC
Content-Type: text/rfc822-headers

X-Bunzzle-Ref: bae2kmxj4wl5wq3ru6gkfyzcjauwrwfqgbydiyc7zt
Subject: hi

--ABC--
`);

const ARF = crlf(`From: staff@hotmail.test
Subject: complaint
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="part1"

--part1
Content-Type: text/plain

This is an email abuse report.

--part1
Content-Type: message/feedback-report

Feedback-Type: abuse
User-Agent: SomeGenerator/1.0
Version: 1
Original-Rcpt-To: <someone@hotmail.test>

--part1
Content-Type: message/rfc822

From: <news@sender.test>
X-Bunzzle-Ref: bae2kmxj4wl5wq3ru6gkfyzcjauwrwfqgbydiyc7zt
Subject: newsletter

body
--part1--
`);

const AUTO = crlf(`From: someone@example.test
Subject: Out of office
Auto-Submitted: auto-replied
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

I'm away =E2=80=94 back Monday.
`);

const QMAIL = crlf(`From: MAILER-DAEMON@example.test
Subject: failure notice

Hi. This is the qmail-send program at example.test.
I'm afraid I wasn't able to deliver your message to the following addresses.

<nobody@example.test>:
550 5.1.1 mailbox unavailable
`);

const MIME_WORDS = [
  "=?UTF-8?B?w4dh?=",
  "=?iso-8859-1?Q?caf=E9_x?= ",
  "; filename*0*=UTF-8''%C3%A7",
  '; filename*1="b"',
  "Content-Type: text/plain; charset=koi8-r\r\n",
  "Content-Type: multipart/digest; boundary=ABC\r\n",
  "\r\n",
  "\r\n\r\n",
  "--ABC\r\n",
  "--ABC--\r\n",
  "--part1\r\n",
  'Content-Type: multipart/mixed; boundary="ABC"\r\n',
  "Content-Type: message/rfc822\r\n",
  "Content-Type: message/delivery-status\r\n",
  "Content-Type: message/feedback-report\r\n",
  "Content-Transfer-Encoding: base64\r\n",
  "Content-Transfer-Encoding: quoted-printable\r\n",
  "Final-Recipient: rfc822; a@b\r\n",
  "Status: 5.1.1\r\n",
  "Action: failed\r\n",
  "X-Bunzzle-Ref: ",
  "\t",
  " ",
  "=?utf-8?b?",
  "=\r\n",
  ":",
  ";",
];

describe("fuzz: parsers that see outside data", () => {
  test(
    "DNS responses",
    async () => {
      const findings = await fuzz({
        seeds: DNS_SEEDS,
        dictionary: ["\xc0\x0c", "\xc0\x00", "\x3f", "\x00\x0f", "\x00\x10", "\xff\xff"],
        maxLength: 4096,
        iterations: 5,
        expected: (e) => e instanceof DnsWireError,
        run(input) {
          const m = decodeMessage(input);
          expect(m.answers.length + m.authority.length).toBeLessThanOrEqual(input.length);
          for (const rec of [...m.answers, ...m.authority]) {
            expect(rec.name.length).toBeLessThanOrEqual(253);
            if (rec.type === "MX") expect(rec.mx.exchange.length).toBeLessThanOrEqual(253);
          }
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "bounce, complaint and auto-reply messages",
    async () => {
      const findings = await fuzz({
        seeds: [DSN, ARF, AUTO, QMAIL],
        dictionary: MIME_WORDS,
        maxLength: 128 * 1024,
        iterations: 3,
        expected: (e) => e instanceof MimeParseError,
        run(input) {
          const r = classifyReport(latin1.decode(input));
          if (r.kind === "dsn")
            expect(r.recipients.length).toBeLessThanOrEqual(MIME_LIMITS.maxHeaders);
          if (r.kind === "bounce") expect(r.addresses.length).toBeLessThanOrEqual(input.length);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "deeply nested and oversized MIME is refused, not recursed into",
    () => {
      let nested = "Subject: x\r\n\r\nend";
      for (let i = 0; i < 2_000; i++) {
        nested = `Content-Type: message/rfc822\r\n\r\n${nested}`;
      }
      const many = `Content-Type: multipart/mixed; boundary=B\r\n\r\n${"--B\r\n\r\nx\r\n".repeat(5_000)}--B--\r\n`;
      const headers = `${"X-A: 1\r\n".repeat(10_000)}\r\nbody`;
      for (const raw of [nested, many, headers]) {
        const started = performance.now();
        try {
          classifyReport(raw);
        } catch (e) {
          expect(e).toBeInstanceOf(MimeParseError);
        }
        expect(performance.now() - started).toBeLessThan(1_000);
      }
    },
    LONG,
  );

  test(
    "MIME parser",
    async () => {
      const findings = await fuzz({
        seeds: [DSN, ARF, AUTO, QMAIL],
        dictionary: MIME_WORDS,
        maxLength: 128 * 1024,
        iterations: 3,
        expected: (e) => e instanceof MimeParseError,
        run(input) {
          const parts = walkParts(parseMime(input));
          expect(parts.length).toBeLessThanOrEqual(MIME_LIMITS.maxParts);
          for (const p of parts) {
            expect(p.content.length).toBeLessThanOrEqual(input.length);
            for (const v of p.headers.values()) for (const h of v) decodeWords(h);
          }
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "address lists",
    async () => {
      const findings = await fuzz({
        seeds: [
          '"Doe, John" <j@x.test>, k@y.test (Kay (nested) \\) ), =?UTF-8?Q?A=2C_B?= <ab@x.test>',
          'Team: a@x.test, "B" <b@x.test>;, <@relay.test:r@x.test>, "a b"@[127.0.0.1]',
        ],
        dictionary: ['"', "<", ">", "@", ",", ";", ":", ".", "(", ")", "\\", "[", "]", "\r\n "],
        maxLength: 8 * 1024,
        expected: (e) => e instanceof AddressError,
        run(input) {
          const list = parseAddressList(latin1.decode(input));
          expect(list.length).toBeLessThanOrEqual(input.length);
          for (const a of list) expect(a.address).toContain("@");
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "encoded words and parameters",
    async () => {
      const findings = await fuzz({
        seeds: [
          "=?UTF-8?B?w4dhbMSxxZ9tYQ==?= =?UTF-8?Q?a_b?=",
          'attachment; filename*0*=UTF-8\'\'%C3%A7al; filename*1="x"; name="a;b" (c)',
        ],
        dictionary: MIME_WORDS,
        maxLength: 8 * 1024,
        run(input) {
          const s = latin1.decode(input);
          decodeWords(s);
          const p = parseParams(s);
          expect(p.params.size).toBeLessThanOrEqual(input.length);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "header blocks",
    async () => {
      const findings = await fuzz({
        seeds: [DSN.slice(0, DSN.indexOf("\r\n\r\n")), "A: b\r\n c\r\nD:\r\n"],
        dictionary: MIME_WORDS,
        maxLength: 32 * 1024,
        expected: (e) => e instanceof MimeParseError,
        run(input) {
          const h = parseHeaderBlock(latin1.decode(input));
          expect(h.size).toBeLessThanOrEqual(MIME_LIMITS.maxHeaders);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "MTA-STS policies",
    async () => {
      const findings = await fuzz({
        seeds: [
          "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.example.net\nmax_age: 86400\n",
          "version: STSv1\r\nmode: testing\r\nmx: mail.example.org\r\nmax_age: 604800\r\n",
          "version: STSv1\nmode: none\nmax_age: 1\n",
        ],
        dictionary: ["mx: ", "*.", "mode: ", "enforce", "max_age: ", "9999999999", "\n", ":"],
        maxLength: 64 * 1024,
        run(input) {
          const p = parsePolicy(utf8.decode(input));
          if (!p) return;
          expect(["enforce", "testing", "none"]).toContain(p.mode);
          expect(p.maxAge).toBeGreaterThanOrEqual(0);
          expect(p.maxAge).toBeLessThanOrEqual(31_557_600);
          for (const host of ["mx1.example.com", "a.example.net", "", "."]) mxAllowed(host, p.mx);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "SMTP reply texts through the classifier",
    async () => {
      const phases = ["connect", "greeting", "ehlo", "starttls", "mail", "rcpt", "data", "message"];
      const findings = await fuzz({
        seeds: [
          "5.7.1 Service unavailable, Client host [192.0.2.1] blocked using Spamhaus",
          "4.7.0 Try again in 5 minutes",
          "5.1.1 The email account that you tried to reach does not exist",
          "4.2.1 The user you are trying to contact is receiving mail too quickly",
          "4.7.28 Our system has detected an unusual rate of unsolicited mail",
          "Greylisted, please retry in 300 seconds",
        ],
        dictionary: [
          " in ",
          " minutes",
          " seconds",
          " hours",
          "retry",
          "5.7.1",
          "4.4.2",
          "9999999999",
        ],
        maxLength: 8 * 1024,
        run(input, r) {
          const text = utf8.decode(input);
          const code = pick(r, [null, 421, 450, 451, 452, 550, 552, 553, 554, 250, int(r, 1000)]);
          const c = classify({
            phase: pick(r, phases) as never,
            code,
            enhanced: pick(r, [null, "5.1.1", "4.7.0", "5.7.26", "9.9.9"]),
            text,
            provider: pick(r, [null, "google", "microsoft", "yahoo"]),
            shared: r() < 0.5,
          });
          expect([
            "done",
            "retry",
            "fail-recipient",
            "fail-message",
            "pause-path",
            "slow-path",
          ]).toContain(c.action);
          if (c.suppress) expect(c.scope).toBe("recipient");
          const hint = retryHint(text);
          if (hint !== null) {
            expect(Number.isFinite(hint)).toBe(true);
            expect(hint).toBeGreaterThanOrEqual(0);
          }
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "addresses",
    async () => {
      const findings = await fuzz({
        seeds: [
          "Someone <someone@example.com>",
          '"Last, First" <first.last+tag@sub.example.co.uk>',
          "user@xn--bcher-kva.example",
          "jörg@bücher.example",
          "a@b",
        ],
        dictionary: ["<", ">", "@", '"', ",", "\r\n", ".", "xn--", "\u0000"],
        maxLength: 2048,
        expected: (e) => e instanceof AddressError,
        run(input) {
          const text = utf8.decode(input);
          const a = parseAddress(text);
          expect(a.address).not.toMatch(/[\r\n\0]/);
          expect(a.name ?? "").not.toMatch(/[\r\n]/);
          normalizeAddress(a.address);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "bounce and unsubscribe tokens",
    async () => {
      const master = await masterKeyFrom(generateMasterKey());
      const tokens = await Promise.all([
        makeToken(master, "b", "0199f3a4-7c1e-7d55-9a21-3b6f0c9e4d12"),
        makeToken(master, "u", "0199f3a4-7c1e-7d55-9a21-3b6f0c9e4d12"),
        makeToken(master, "b", "short-id"),
      ]);
      const findings = await fuzz({
        seeds: tokens,
        dictionary: ["a", "z", "2", "7", "=", "-", "0", "1"],
        maxLength: 200,
        iterations: 2,
        async run(input) {
          const text = latin1.decode(input);
          unbase32(text);
          const got = await readToken(master, text);
          if (got === null) return;
          const original = tokens.find((t) => unbase32(t)?.toHex() === unbase32(text)?.toHex());
          expect(original).toBeDefined();
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "DKIM key records",
    async () => {
      const findings = await fuzz({
        seeds: [
          "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx",
          "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
          "DKIM-Signature: v=1; a=rsa-sha256; s=bz1; d=example.com; b=abc\r\n\r\nbody",
        ],
        dictionary: [";", "=", "p=", "k=", "s=", "\r\n", " "],
        maxLength: 8192,
        run(input) {
          const text = utf8.decode(input);
          keyFromTxt(text);
          selectorsOf(text);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "API send requests",
    async () => {
      const base = {
        from: "Shop <hello@example.com>",
        to: ["someone@example.org"],
        cc: "other@example.org",
        subject: "Your order",
        html: "<p>Thanks</p>",
        text: "Thanks",
        reply_to: ["support@example.com"],
        headers: { "X-Order": "42" },
        tags: [{ name: "kind", value: "order" }],
        attachments: [{ filename: "a.txt", content: "aGVsbG8=" }],
        scheduled_at: "2026-10-20T10:00:00Z",
        lane: "transactional",
      };
      const findings = await fuzz({
        seeds: [
          JSON.stringify(base),
          JSON.stringify({ from: "a@b.c", to: "d@e.f", subject: "s", text: "t" }),
          JSON.stringify({
            ...base,
            lane: "bulk",
            to: ["x@y.z"],
            cc: undefined,
            reply_to: undefined,
          }),
        ],
        dictionary: [
          '"',
          "\\r\\n",
          "\\u0000",
          "[",
          "]",
          "{",
          "}",
          ",",
          ":",
          "null",
          "1e999",
          "@",
          "<",
          ">",
        ],
        maxLength: 64 * 1024,
        iterations: 3,
        expected: (e) => e instanceof ApiError,
        run(input) {
          let json: unknown;
          try {
            json = JSON.parse(utf8.decode(input));
          } catch {
            return;
          }
          const parsed = sendSchema.safeParse(json);
          if (!parsed.success) return;
          const email = prepareEmail(parsed.data, new Date("2026-10-16T00:00:00Z"));
          expect(JSON.stringify(email).length).toBeGreaterThan(0);
        },
      });
      expect(report(findings)).toBe("");
    },
    LONG,
  );

  test(
    "SPF records, DKIM signatures and DMARC records",
    async () => {
      let txt = "";
      const resolver: Resolver = {
        async query(name: string, type: QueryType): Promise<DnsAnswer> {
          const base = { name, type, rcode: 0, authenticated: false, ttl: 60 };
          if (type === "TXT") {
            const rr = { name, ttl: 60, rrtype: 16, rdata: new Uint8Array() };
            return { ...base, records: [{ ...rr, type: "TXT", strings: [txt] }] };
          }
          if (type === "A") {
            const rr = { name, ttl: 60, rrtype: 1, rdata: new Uint8Array() };
            return { ...base, records: [{ ...rr, type: "A", address: "192.0.2.1" }] };
          }
          return { ...base, records: [] };
        },
      };
      const spf = await fuzz({
        seeds: [
          "v=spf1 include:%{d} a:%{ir}.%{v}.x/24//64 mx ptr exists:%{l1r-}.%{o} -all",
          "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 redirect=%{d2}.example ~all",
        ],
        dictionary: ["%{", "}", "include:", "redirect=", "/", "//", "ip6:", ":"],
        maxLength: 2048,
        iterations: 3,
        async run(input) {
          txt = latin1.decode(input);
          const r = await checkSpf(resolver, {
            ip: "192.0.2.9",
            mailFrom: "a-b@x.test",
            helo: null,
          });
          expect([
            "pass",
            "fail",
            "softfail",
            "neutral",
            "none",
            "temperror",
            "permerror",
          ]).toContain(r.result);
        },
      });
      expect(report(spf)).toBe("");
      const dkim = await fuzz({
        seeds: [
          crlf(
            "DKIM-Signature: v=1; a=rsa-sha256; c=simple/relaxed; d=x.test; s=s; l=4; t=1; x=2;\n h=from:to; bh=AAAA; b=AAAA\nFrom: a@x.test\n\nbody\n",
          ),
        ],
        dictionary: ["DKIM-Signature:", "; ", "=", "\r\n ", "relaxed", "ed25519-sha256"],
        maxLength: 16 * 1024,
        iterations: 3,
        async run(input) {
          txt = "v=DKIM1; k=rsa; p=AAAA";
          const raw = latin1.decode(input);
          for (const r of await checkDkim(resolver, raw)) expect(r.result).not.toBe("pass");
          fromDomain(raw);
        },
      });
      expect(report(dkim)).toBe("");
      const dmarc = await fuzz({
        seeds: ["v=DMARC1; p=reject; sp=none; np=quarantine; adkim=s; aspf=r; pct=50; t=y; psd=n"],
        dictionary: [";", "=", "v=DMARC1", "p=", "psd=y"],
        maxLength: 1024,
        iterations: 5,
        run(input) {
          parseDmarcRecord(utf8.decode(input));
        },
      });
      expect(report(dmarc)).toBe("");
    },
    LONG,
  );
});
