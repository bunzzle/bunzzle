import { describe, expect, test } from "bun:test";
import {
  headerData,
  relaxedBody,
  relaxedHeader,
  splitMessage,
} from "../../src/dkim/canonicalize.ts";
import { dnsRecords, generateKeyFile, importKeys, parseKeyFile } from "../../src/dkim/keys.ts";
import { headerList, signData, signMessage } from "../../src/dkim/sign.ts";
import { buildMessage } from "../../src/mime/builder.ts";
import { type PublicKey, verifyDkim } from "../support/dkim-verify.ts";

const RFC_MESSAGE = (await Bun.file(`${import.meta.dir}/../fixtures/rfc8463.eml`).text()).replace(
  /\r?\n/g,
  "\r\n",
);

const RFC_KEYS: Record<string, PublicKey> = {
  brisbane: {
    algorithm: "ed25519-sha256",
    key: Uint8Array.fromBase64("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),
  },
  test: {
    algorithm: "rsa-sha256",
    key: Uint8Array.fromBase64(
      "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB",
    ),
  },
};

const ED25519_SEED = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

function publicKeysOf(file: Awaited<ReturnType<typeof generateKeyFile>>) {
  const out: Record<string, PublicKey> = {};
  for (const k of file.keys) {
    out[k.selector] = { algorithm: k.algorithm, key: Uint8Array.fromBase64(k.publicKey) };
  }
  return out;
}

function sample() {
  return buildMessage({
    from: { address: "hello@bunzzle.com", name: "Bunzzle" },
    to: [{ address: "you@example.org" }],
    subject: "Hello from Bunzzle",
    text: "First line\nSecond line   \n\n\n",
    html: "<p>Hello</p>",
    messageId: "<abc@bunzzle.com>",
    date: new Date("2026-10-15T12:00:00Z"),
  }).raw;
}

describe("canonicalization", () => {
  test("relaxed header unfolds, lowercases the name and collapses whitespace", () => {
    expect(relaxedHeader("SubJect :  Hello \t  world  \r\n   again ")).toBe(
      "subject:Hello world again",
    );
  });

  test("relaxed body strips trailing whitespace and empty lines", () => {
    expect(relaxedBody("a  b \t\r\nc\r\n\r\n\r\n")).toBe("a b\r\nc\r\n");
    expect(relaxedBody("\r\n\r\n")).toBe("");
    expect(relaxedBody("")).toBe("");
  });
});

describe("RFC 8463 test vectors", () => {
  test("both signatures of the RFC example verify with our canonicalization", async () => {
    const verdicts = await verifyDkim(RFC_MESSAGE, RFC_KEYS);
    expect(verdicts).toEqual([
      { selector: "brisbane", ok: true },
      { selector: "test", ok: true },
    ]);
  });

  test("Ed25519 signing reproduces the RFC signature byte for byte", async () => {
    const pkcs8 = new Uint8Array([
      ...Uint8Array.fromHex("302e020100300506032b657004220420"),
      ...Uint8Array.fromBase64(ED25519_SEED),
    ]);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, [
      "sign",
    ]);
    const { headers } = splitMessage(RFC_MESSAGE);
    const sigHeader = headers[0];
    if (!sigHeader) throw new Error("fixture has no headers");
    const names = "from:to:subject:date:message-id:from:subject:date".split(":");
    const stripped = sigHeader.raw.replace(/(;\s*b=)[^;]*$/, "$1");
    const b = await signData(
      {
        domain: "football.example.com",
        selector: "brisbane",
        algorithm: "ed25519-sha256",
        privateKey,
      },
      headerData(headers, names) + relaxedHeader(stripped),
    );
    expect(b).toBe(
      "/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11BusFa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==",
    );
  });
});

describe("signMessage", () => {
  test("adds an RSA and an Ed25519 signature that both verify", async () => {
    const file = await generateKeyFile("bunzzle.com", "bz1");
    const signed = await signMessage(sample(), await importKeys(file));
    const verdicts = await verifyDkim(signed, publicKeysOf(file));
    expect(verdicts.map((v) => v.ok)).toEqual([true, true]);
    expect(signed).not.toContain("l=");
    expect(signed).toContain("c=relaxed/relaxed");
  });

  test("tampering with the body or a signed header breaks the signatures", async () => {
    const file = await generateKeyFile("bunzzle.com", "bz1");
    const signed = await signMessage(sample(), await importKeys(file));
    const keys = publicKeysOf(file);
    const body = await verifyDkim(signed.replace("First line", "Fist line"), keys);
    expect(body.every((v) => !v.ok)).toBe(true);
    const subject = await verifyDkim(signed.replace("Hello from Bunzzle", "Hi"), keys);
    expect(subject.every((v) => !v.ok)).toBe(true);
  });

  test("over-signing: a second From header added later breaks the signatures", async () => {
    const file = await generateKeyFile("bunzzle.com", "bz1");
    const signed = await signMessage(sample(), await importKeys(file));
    const sep = signed.indexOf("\r\n\r\n");
    const forged = `${signed.slice(0, sep)}\r\nFrom: attacker@evil.example${signed.slice(sep)}`;
    const verdicts = await verifyDkim(forged, publicKeysOf(file));
    expect(verdicts.every((v) => !v.ok)).toBe(true);
  });

  test("header list signs present headers once and over-signs the protected ones", () => {
    const { headers } = splitMessage(sample());
    const h = headerList(headers);
    expect(h.filter((n) => n === "from")).toHaveLength(2);
    expect(h.filter((n) => n === "message-id")).toHaveLength(1);
    expect(h).toContain("cc");
    expect(h).not.toContain("references");
  });
});

describe("key files", () => {
  test("generates RSA-2048 and Ed25519 keys with matching DNS records", async () => {
    const file = await generateKeyFile("Bunzzle.com", "bz1");
    expect(file.domain).toBe("bunzzle.com");
    const records = dnsRecords(file);
    expect(records.map((r) => r.name)).toEqual([
      "bz1r._domainkey.bunzzle.com",
      "bz1e._domainkey.bunzzle.com",
    ]);
    expect(records[0]?.value).toStartWith("v=DKIM1; k=rsa; p=MIIBIjAN");
    expect(records[1]?.value).toMatch(/^v=DKIM1; k=ed25519; p=[A-Za-z0-9+/]{43}=$/);
  });

  test("rejects malformed key files", () => {
    expect(() => parseKeyFile({ domain: "x.com", keys: [] })).toThrow("invalid DKIM key file");
  });
});
