import { describe, expect, test } from "bun:test";
import {
  AddressError,
  formatAddress,
  normalizeAddress,
  parseAddress,
  parseAddressList,
} from "../../src/mime/address.ts";
import { buildMessage, type MessageInput, MimeError } from "../../src/mime/builder.ts";
import {
  encodedWords,
  foldHeader,
  quotedPrintable,
  rfc5322Date,
} from "../../src/mime/encodings.ts";

const base: MessageInput = {
  from: { address: "hello@bunzzle.com" },
  to: [{ address: "you@example.org" }],
  subject: "Hi",
  text: "Hello",
  messageId: "<id@bunzzle.com>",
  date: new Date("2026-10-15T09:05:03Z"),
};

function decodeQp(s: string): string {
  const bytes = s
    .replace(/=\r\n/g, "")
    .replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(Number.parseInt(h, 16)));
  return new TextDecoder().decode(Uint8Array.from(bytes, (c) => c.charCodeAt(0)));
}

describe("encodings", () => {
  test("quoted-printable round-trips UTF-8 and keeps lines at most 76 characters", () => {
    const text = `Grüße ${"é".repeat(60)} = done \nnext\tline\t`;
    const qp = quotedPrintable(text);
    for (const line of qp.split("\r\n")) expect(line.length).toBeLessThanOrEqual(76);
    expect(qp).toContain("=3D");
    expect(qp.split("\r\n")[0]).not.toEndWith(" ");
    expect(decodeQp(qp)).toBe(text.replace("\n", "\r\n"));
  });

  test("encoded words never split a multi-byte character", () => {
    const words = encodedWords("😀".repeat(30)).split(" ");
    const decoded = words.map((w) =>
      new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.fromBase64(w.slice(10, -2))),
    );
    expect(decoded.join("")).toBe("😀".repeat(30));
  });

  test("folds long headers at spaces", () => {
    const folded = foldHeader(
      "To",
      Array.from({ length: 10 }, (_, i) => `user${i}@example.org,`).join(" "),
    );
    for (const line of folded.split("\r\n")) expect(line.length).toBeLessThanOrEqual(78);
    expect(folded.split("\r\n")[0]).toStartWith("To: user0");
  });

  test("formats dates per RFC 5322", () => {
    expect(rfc5322Date(new Date("2026-10-15T09:05:03Z"))).toBe("Thu, 15 Oct 2026 09:05:03 +0000");
  });
});

describe("addresses", () => {
  test("parses display names and normalizes domains", () => {
    expect(parseAddress('"Doe, Jane" <Jane@Example.ORG>')).toEqual({
      name: "Doe, Jane",
      address: "Jane@example.org",
    });
    expect(parseAddress("x@bücher.de")).toEqual({ address: "x@xn--bcher-kva.de" });
  });

  test("rejects invalid addresses", () => {
    for (const bad of [
      "no-at",
      "a@",
      "@b.com",
      "a b@c.com",
      "a@nodot",
      "a..b@c.com",
      "a@b.com\r\nBcc: x@y.z",
    ]) {
      expect(() => normalizeAddress(bad)).toThrow(AddressError);
    }
  });

  test("quotes or encodes display names", () => {
    expect(formatAddress({ name: "Jane Doe", address: "j@x.org" })).toBe("Jane Doe <j@x.org>");
    expect(formatAddress({ name: "Doe, Jane", address: "j@x.org" })).toBe('"Doe, Jane" <j@x.org>');
    expect(formatAddress({ name: "Zoë", address: "z@x.org" })).toBe(
      "=?UTF-8?B?Wm/Dqw==?= <z@x.org>",
    );
  });
});

describe("buildMessage", () => {
  test("plain text message has the expected headers and CRLF line endings", () => {
    const { raw, smtpUtf8 } = buildMessage(base);
    expect(raw).toBe(
      "From: hello@bunzzle.com\r\nTo: you@example.org\r\nSubject: Hi\r\nDate: Thu, 15 Oct 2026 09:05:03 +0000\r\n" +
        "Message-ID: <id@bunzzle.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n" +
        "Content-Transfer-Encoding: 7bit\r\n\r\nHello\r\n",
    );
    expect(smtpUtf8).toBe(false);
  });

  test("text and html become multipart/alternative, attachments multipart/mixed", () => {
    const { raw } = buildMessage({
      ...base,
      html: "<p>Hello</p>",
      attachments: [
        {
          filename: "résumé.pdf",
          content: new Uint8Array(100).fill(7),
          contentType: "application/pdf",
        },
      ],
    });
    expect(raw).toMatch(/Content-Type: multipart\/mixed; boundary="bz_[0-9a-f]{24}"/);
    expect(raw).toMatch(/Content-Type: multipart\/alternative; boundary="bz_[0-9a-f]{24}"/);
    expect(raw).toContain("Content-Type: text/html; charset=utf-8");
    expect(raw).toContain("filename*=UTF-8''r%C3%A9sum%C3%A9.pdf");
    expect(raw).toContain(new Uint8Array(100).fill(7).toBase64().slice(0, 76));
    expect(/[\u0080-\uffff]/.test(raw)).toBe(false);
  });

  test("blocks header injection", () => {
    expect(() => buildMessage({ ...base, subject: "Hi\r\nBcc: x@y.z" })).toThrow(MimeError);
    expect(() => buildMessage({ ...base, headers: { "X-Test": "a\nb" } })).toThrow(MimeError);
    expect(() => buildMessage({ ...base, headers: { From: "x@y.z" } })).toThrow(MimeError);
    expect(() => buildMessage({ ...base, headers: { "Bad Name": "x" } })).toThrow(MimeError);
    expect(() =>
      buildMessage({ ...base, headers: { References: "<a@x.org>", references: "<b@x.org>" } }),
    ).toThrow(MimeError);
  });

  test("custom headers are kept", () => {
    const { raw } = buildMessage({ ...base, headers: { "List-Unsubscribe": "<https://x.org/u>" } });
    expect(raw).toContain("List-Unsubscribe: <https://x.org/u>\r\n");
  });

  test("non-ASCII local parts require SMTPUTF8", () => {
    expect(buildMessage({ ...base, to: [{ address: "jösé@example.org" }] }).smtpUtf8).toBe(true);
  });

  test("long lines are encoded, never sent over 998 characters", () => {
    const { raw } = buildMessage({ ...base, text: "x".repeat(5000) });
    expect(raw).toContain("quoted-printable");
    for (const line of raw.split("\r\n")) expect(line.length).toBeLessThanOrEqual(998);
  });
});

describe("parseAddressList", () => {
  test("names, groups, comments, quoted local parts and literals", () => {
    expect(
      parseAddressList(
        '"Doe, John" <j@x.test>, k@y.test (Kay), =?UTF-8?Q?A=2C_B?= <ab@x.test>, John Q. Public <q@x.test>',
      ),
    ).toEqual([
      { address: "j@x.test", name: "Doe, John" },
      { address: "k@y.test" },
      { address: "ab@x.test", name: "A, B" },
      { address: "q@x.test", name: "John Q. Public" },
    ]);
    expect(parseAddressList("undisclosed-recipients:;")).toEqual([]);
    expect(
      parseAddressList('Team: a@x.test, "B" <b@x.test>;, c@x.test').map((a) => a.address),
    ).toEqual(["a@x.test", "b@x.test", "c@x.test"]);
    expect(
      parseAddressList('"a b"@x.test, "plain"@x.test, a@[127.0.0.1], <@r.test:r@x.test>,,').map(
        (a) => a.address,
      ),
    ).toEqual(['"a b"@x.test', "plain@x.test", "a@[127.0.0.1]", "r@x.test"]);
  });

  test("malformed lists are refused", () => {
    for (const v of [
      "Doe, John <j@x.test>",
      "a@",
      "<a@x.test",
      '"open',
      "(open a@x.test",
      "G: a@x.test",
      "a@x.test b@x.test",
    ]) {
      expect(() => parseAddressList(v)).toThrow(AddressError);
    }
  });
});
