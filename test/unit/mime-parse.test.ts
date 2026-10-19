import { describe, expect, test } from "bun:test";
import { buildMessage } from "../../src/mime/builder.ts";
import {
  decodeCharset,
  decodeWords,
  fromBinary,
  headerText,
  MIME_LIMITS,
  MimeParseError,
  parseMime,
  parseParams,
  toBinary,
  walkParts,
} from "../../src/mime/parse.ts";

const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");
const bytes = (...xs: number[]) => Uint8Array.from(xs);

describe("encoded words", () => {
  test("base64 and Q words in several charsets", () => {
    expect(decodeWords("=?UTF-8?B?w4dhbMSxxZ9tYQ==?=")).toBe("Çalışma");
    expect(decodeWords("=?ISO-8859-1?Q?Caf=E9_cr=E8me?=")).toBe("Café crème");
    expect(decodeWords("=?koi8-r?B?8NLJ18XU?=")).toBe("Привет");
    expect(decodeWords("=?iso-2022-jp?B?GyRCJCIbKEI=?=")).toBe("あ");
  });

  test("whitespace between adjacent words is dropped, other text kept", () => {
    expect(decodeWords("=?UTF-8?Q?a?= =?UTF-8?Q?b?=")).toBe("ab");
    expect(decodeWords("Re: =?UTF-8?Q?caf=C3=A9?= now")).toBe("Re: café now");
  });

  test("a character split across two words is joined before decoding", () => {
    expect(decodeWords("=?UTF-8?B?w4c=?= =?UTF-8?B?YQ==?=")).toBe("Ça");
    expect(decodeWords("=?UTF-8?Q?=C3?= =?UTF-8?Q?=87?=")).toBe("Ç");
  });

  test("language suffix and unknown charset", () => {
    expect(decodeWords("=?UTF-8*en?Q?hi?=")).toBe("hi");
    expect(decodeWords("=?x-nope?Q?plain?=")).toBe("plain");
  });

  test("raw UTF-8 bytes in a header", () => {
    expect(decodeWords(toBinary(new TextEncoder().encode("Ünlü")))).toBe("Ünlü");
  });
});

describe("parameters", () => {
  test("quoted values with semicolons and comments", () => {
    const p = parseParams('multipart/mixed (note); boundary="a;b"; charset=utf-8 (x)');
    expect(p.value).toBe("multipart/mixed");
    expect(p.params.get("boundary")).toBe("a;b");
    expect(p.params.get("charset")).toBe("utf-8");
  });

  test("RFC 2231 continuations and charset", () => {
    const p = parseParams(
      "attachment; filename*0*=UTF-8''%C3%A7al; filename*1=\"is ma\"; filename*2*=%2Etxt",
    );
    expect(p.value).toBe("attachment");
    expect(new TextDecoder().decode(fromBinary(p.params.get("filename") as string))).toBe(
      "çalis ma.txt",
    );
  });

  test("first value wins over a repeat", () => {
    expect(parseParams("text/plain; charset=utf-8; charset=latin1").params.get("charset")).toBe(
      "utf-8",
    );
  });
});

describe("charsets", () => {
  test("labels Bun knows, unknown labels and mislabeled UTF-8", () => {
    expect(decodeCharset(bytes(0xe9), "iso-8859-1")).toBe("é");
    expect(decodeCharset(bytes(0xa4), "iso-8859-15")).toBe("€");
    expect(decodeCharset(bytes(0xc3, 0xa9), "us-ascii")).toBe("é");
    expect(decodeCharset(bytes(0xc3, 0xa9), "x-unknown")).toBe("é");
    expect(decodeCharset(bytes(0xe9), null)).toBe("é");
  });
});

describe("parseMime", () => {
  test("round trip through our own builder", () => {
    const built = buildMessage({
      from: { address: "a@example.com", name: "Ayşe" },
      to: [{ address: "b@example.com" }],
      subject: "Merhaba dünya, bu uzun bir konu satırıdır ve katlanması gerekir",
      text: "Satır bir\nSatır iki ğüşiöç",
      html: "<p>Merhaba ğüşiöç</p>",
      attachments: [
        {
          filename: "rapor ğ.txt",
          content: new TextEncoder().encode("içerik"),
          contentType: "text/plain",
        },
      ],
      messageId: "<x@example.com>",
      date: new Date(0),
    });
    const root = parseMime(built.raw);
    expect(headerText(root, "Subject")).toBe(
      "Merhaba dünya, bu uzun bir konu satırıdır ve katlanması gerekir",
    );
    const parts = walkParts(root);
    const text = parts.find((p) => p.type === "text/plain" && !p.filename);
    const html = parts.find((p) => p.type === "text/html");
    const file = parts.find((p) => p.filename);
    expect(text?.body.replace(/\r\n/g, "\n")).toBe("Satır bir\nSatır iki ğüşiöç");
    expect(html?.body).toBe("<p>Merhaba ğüşiöç</p>");
    expect(file?.filename).toBe("rapor ğ.txt");
    expect(file?.disposition).toBe("attachment");
    expect(new TextDecoder().decode(file?.content)).toBe("içerik");
  });

  test("delimiters only count at the start of a line, and a longer boundary is not a match", () => {
    const raw = crlf(`Content-Type: multipart/mixed; boundary=b

pre --b not a delimiter
--b
Content-Type: multipart/alternative; boundary=bb

--bb

inner
--bb--
--b

second --b
--b--
epilogue`);
    const root = parseMime(raw);
    expect(root.parts.length).toBe(2);
    expect(root.parts[0]?.type).toBe("multipart/alternative");
    expect(root.parts[0]?.parts[0]?.body).toBe("inner");
    expect(root.parts[1]?.body).toBe("second --b");
  });

  test("missing closing delimiter keeps the last part", () => {
    const root = parseMime(crlf("Content-Type: multipart/mixed; boundary=z\n\n--z\n\nonly"));
    expect(root.parts.map((p) => p.body)).toEqual(["only"]);
  });

  test("8-bit body bytes keep their charset", () => {
    const head = "Content-Type: text/plain; charset=windows-1251\r\n\r\n";
    const body = parseMime(Uint8Array.from([...new TextEncoder().encode(head), 0xcf, 0xf0, 0xe8]));
    expect(body.body).toBe("При");
  });

  test("base64 that is broken or unpadded still decodes what it can", () => {
    const raw = "Content-Transfer-Encoding: base64\r\n\r\naGVs\r\nbG8*\r\n";
    expect(parseMime(raw).body).toBe("hello");
  });

  test("quoted-printable soft breaks and bad escapes", () => {
    const raw =
      "Content-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ncaf=C3=A9 =\r\nau =ZZ lait";
    expect(parseMime(raw).body).toBe("café au =ZZ lait");
  });

  test("a message part is parsed as a nested message, also inside a digest", () => {
    const raw = crlf(`Content-Type: multipart/digest; boundary=d

--d

Subject: =?UTF-8?Q?ilk?=

one
--d--`);
    const inner = parseMime(raw).parts[0];
    expect(inner?.type).toBe("message/rfc822");
    expect(headerText(inner?.parts[0] as never, "subject")).toBe("ilk");
  });

  test("headers: folding, mbox line, bad names and repeats", () => {
    const raw =
      "From sender Mon Jan 1\r\nReceived: a\r\nReceived: b\r\nSubject: one\r\n\ttwo\r\nBad Name: x\r\n: empty\r\n\r\nbody";
    const root = parseMime(raw);
    expect(root.headers.get("received")).toEqual(["a", "b"]);
    expect(root.headers.get("subject")).toEqual(["one two"]);
    expect(root.headers.has("bad name")).toBe(false);
    expect(root.headers.has("from sender mon jan 1")).toBe(false);
  });

  test("no headers and no body", () => {
    expect(parseMime("\r\njust body").body).toBe("just body");
    expect(parseMime("").type).toBe("text/plain");
  });

  test("limits", () => {
    let nested = "x";
    for (let i = 0; i <= MIME_LIMITS.maxDepth + 1; i++)
      nested = `Content-Type: message/rfc822\r\n\r\n${nested}`;
    expect(() => parseMime(nested)).toThrow(MimeParseError);
    const many = `Content-Type: multipart/mixed; boundary=B\r\n\r\n${"--B\r\n\r\nx\r\n".repeat(MIME_LIMITS.maxParts + 1)}--B--`;
    expect(() => parseMime(many)).toThrow("too many MIME parts");
    const flood = `${"X: 1\r\n".repeat(MIME_LIMITS.maxHeaders + 1)}\r\nb`;
    expect(() => parseMime(flood)).toThrow("too many headers");
  });

  test("large input stays fast", () => {
    const body = "a".repeat(80).concat("\r\n").repeat(100_000);
    const raw = `Content-Type: multipart/mixed; boundary=q\r\n\r\n--q\r\n\r\n${body}--q--\r\n`;
    const started = performance.now();
    expect(parseMime(raw).parts.length).toBe(1);
    expect(performance.now() - started).toBeLessThan(500);
  });
});
