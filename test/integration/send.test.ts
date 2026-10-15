import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { type KeyFile, parseKeyFile } from "../../src/dkim/keys.ts";
import { type PublicKey, verifyDkim } from "../support/dkim-verify.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
let dir: string;
let dns: FakeDns;
let mx: FakeMx;
let keys: KeyFile;

async function cli(args: string[], env: Record<string, string> = {}) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    env: {
      PATH: process.env["PATH"] ?? "",
      BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
      BUNZZLE_SMTP_PORT: String(mx.port),
      BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
      BUNZZLE_EHLO_NAME: "out.bunzzle.test",
      ...env,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, code };
}

beforeAll(async () => {
  dir = (await Bun.$`mktemp -d`.text()).trim();
  dns = await startFakeDns({
    "example.test": { MX: [[10, "mx.example.test"]] },
    "mx.example.test": { A: ["127.0.0.1"] },
    "nullmx.test": { MX: [[0, ""]] },
  });
  mx = startFakeMx({
    rcpt: (a) => (a.startsWith("nobody") ? "550 5.1.1 User unknown\r\n" : "250 2.1.5 Ok\r\n"),
  });
  const r = await cli([
    "dkim",
    "keygen",
    "--domain",
    "bunzzle.test",
    "--selector",
    "t1",
    "--out",
    `${dir}/dkim.json`,
  ]);
  expect(r.code).toBe(0);
  keys = parseKeyFile(await Bun.file(`${dir}/dkim.json`).json());
});

afterAll(async () => {
  dns.stop();
  mx.stop();
  await Bun.$`rm -rf ${dir}`;
});

function publicKeys(): Record<string, PublicKey> {
  return Object.fromEntries(
    keys.keys.map((k) => [
      k.selector,
      { algorithm: k.algorithm, key: Uint8Array.fromBase64(k.publicKey) },
    ]),
  );
}

describe("bunzzle dkim", () => {
  test("keygen writes a private key file and prints both DNS records", async () => {
    const r = await cli(["dkim", "records", "--keys", `${dir}/dkim.json`]);
    expect(r.stdout).toContain("t1r._domainkey.bunzzle.test");
    expect(r.stdout).toContain("t1e._domainkey.bunzzle.test");
    expect(r.stdout).toContain("k=ed25519");
    const { mode } = await Bun.file(`${dir}/dkim.json`).stat();
    expect(mode & 0o777).toBe(0o600);
  });

  test("keygen refuses to overwrite keys", async () => {
    const r = await cli([
      "dkim",
      "keygen",
      "--domain",
      "bunzzle.test",
      "--out",
      `${dir}/dkim.json`,
    ]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("already exists");
  });
});

describe("bunzzle send", () => {
  test("delivers a DKIM-signed email and reports MX, TLS and the reply", async () => {
    const before = mx.sessions.length;
    const r = await cli([
      "send",
      "--from",
      "Bunzzle <hello@bunzzle.test>",
      "--to",
      "you@example.test",
      "--subject",
      "First email",
      "--text",
      "Hello from Bunzzle",
      "--dkim-keys",
      `${dir}/dkim.json`,
    ]);
    expect(r.stderr).toBe("");
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("MX: mx.example.test");
    expect(r.stdout).toContain("→ mx.example.test [127.0.0.1]");
    expect(r.stdout).toMatch(/TLSv1\.[23] \S+, certificate unverified/);
    expect(r.stdout).toContain("delivered you@example.test  250 Ok: queued as 12345");
    const received = mx.sessions[before]?.messages[0] ?? "";
    expect(received).toContain("Subject: First email");
    const verdicts = await verifyDkim(received, publicKeys());
    expect(verdicts.map((v) => [v.selector, v.ok])).toEqual([
      ["t1r", true],
      ["t1e", true],
    ]);
  });

  test("reports per-recipient failures and exits 1", async () => {
    const r = await cli([
      "send",
      "--from",
      "hello@bunzzle.test",
      "--to",
      "you@example.test",
      "--to",
      "nobody@example.test",
      "--cc",
      "x@nullmx.test",
      "--subject",
      "Mixed",
      "--text",
      "Hi",
      "--dkim-keys",
      `${dir}/dkim.json`,
      "--json",
    ]);
    expect(r.code).toBe(1);
    const out = JSON.parse(r.stdout) as {
      reports: {
        recipients: { address: string; status: string; verdict: { class: string } }[];
      }[];
    };
    const classes = Object.fromEntries(
      out.reports.flatMap((x) => x.recipients).map((x) => [x.address, x.verdict.class]),
    );
    expect(classes).toEqual({
      "you@example.test": "accepted",
      "nobody@example.test": "user-unknown",
      "x@nullmx.test": "null-mx",
    });
    const statuses = Object.fromEntries(
      out.reports.flatMap((x) => x.recipients).map((x) => [x.address, x.status]),
    );
    expect(statuses).toEqual({
      "you@example.test": "delivered",
      "nobody@example.test": "bounced",
      "x@nullmx.test": "bounced",
    });
  });

  test("explains a rejected recipient in plain words", async () => {
    const r = await cli([
      "send",
      "--from",
      "hello@bunzzle.test",
      "--to",
      "nobody@example.test",
      "--subject",
      "x",
      "--text",
      "x",
      "--dkim-keys",
      `${dir}/dkim.json`,
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain(
      "bounced   nobody@example.test  550 User unknown  [user-unknown, about the recipient, recipient failed, would suppress]",
    );
  });

  test("refuses to sign for a domain the keys do not belong to", async () => {
    const r = await cli([
      "send",
      "--from",
      "ceo@other.test",
      "--to",
      "you@example.test",
      "--subject",
      "x",
      "--text",
      "x",
      "--dkim-keys",
      `${dir}/dkim.json`,
    ]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("only signs for the sender's own domain");
  });

  test("refuses to send without DKIM unless --unsigned is given", async () => {
    const r = await cli([
      "send",
      "--from",
      "a@bunzzle.test",
      "--to",
      "you@example.test",
      "--subject",
      "x",
      "--text",
      "x",
    ]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("no DKIM keys");
  });

  test("--dry-run prints the signed message without connecting", async () => {
    const before = mx.sessions.length;
    const r = await cli([
      "send",
      "--from",
      "a@bunzzle.test",
      "--to",
      "you@example.test",
      "--subject",
      "Dry",
      "--text",
      "x",
      "--dkim-keys",
      `${dir}/dkim.json`,
      "--dry-run",
    ]);
    expect(r.code).toBe(0);
    expect(r.stdout).toStartWith("DKIM-Signature: v=1; a=rsa-sha256;");
    expect(mx.sessions.length).toBe(before);
  });

  test("bad input exits 2 with a clear message", async () => {
    const r = await cli([
      "send",
      "--from",
      "not-an-address",
      "--to",
      "you@example.test",
      "--subject",
      "x",
      "--text",
      "x",
    ]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("invalid email address");
  });
});
