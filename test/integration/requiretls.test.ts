import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createResolver } from "../../src/dns/resolver.ts";
import { deliver } from "../../src/smtp/deliver.ts";
import type { StsPolicy } from "../../src/smtp/mta-sts.ts";
import type { RequireTlsMode } from "../../src/smtp/session.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { DEFAULT_EXTENSIONS, type FakeMx, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const WRONG = "00".repeat(32);
const STS: StsPolicy = {
  domain: "plain.test",
  id: "1",
  mode: "enforce",
  mx: ["mx.example.test"],
  maxAge: 86_400,
  fetchedAt: Date.now(),
};
const zone: Zone = {
  "signed.test": { MX: [[10, "mx.example.test"]], secure: true },
  "mx.example.test": { A: ["127.0.0.1"], secure: true },
  "plain.test": { MX: [[10, "mx.example.test"]] },
  "pinned.test": { MX: [[10, "mx.pinned.test"]], secure: true },
  "mx.pinned.test": { A: ["127.0.0.1"], secure: true },
  "_25._tcp.mx.pinned.test": { TLSA: [[3, 1, 1, WRONG]], secure: true },
};

let dns: FakeDns;
let supporting: FakeMx;
let lacking: FakeMx;

beforeAll(async () => {
  dns = await startFakeDns(zone);
  supporting = startFakeMx({ extensions: [...DEFAULT_EXTENSIONS, "REQUIRETLS"] });
  lacking = startFakeMx();
});

afterAll(() => {
  dns.stop();
  supporting.stop();
  lacking.stop();
});

interface Case {
  domain: string;
  mx: FakeMx;
  requireTls?: boolean;
  mode?: RequireTlsMode;
  ca?: boolean;
  headers?: string;
  sts?: boolean;
}

function send(c: Case) {
  return deliver(
    {
      domain: c.domain,
      from: "a@bunzzle.test",
      recipients: [`x@${c.domain}`],
      data: `From: a@bunzzle.test\r\n${c.headers ?? ""}Subject: x\r\n\r\nx\r\n`,
      smtpUtf8: false,
      requireTls: c.requireTls ?? true,
      ...(c.sts ? { sts: STS } : {}),
    },
    {
      resolver: createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] }),
      ehloName: "out.bunzzle.test",
      port: c.mx.port,
      allowPrivate: true,
      ...(c.ca === false ? {} : { tlsCa: TEST_CA }),
      timeouts: { greeting: 2_000, quit: 200 },
      dane: true,
      requiretls: c.mode ?? "enforce",
    },
  );
}

const mailFrom = (mx: FakeMx) =>
  mx.sessions.at(-1)?.commands.find((l) => l.toUpperCase().startsWith("MAIL FROM")) ?? null;

describe("REQUIRETLS when sending", () => {
  test("a signed MX with a verified certificate that supports it: sent with REQUIRETLS", async () => {
    const r = await send({ domain: "signed.test", mx: supporting });
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.policy).toMatchObject({ rule: "requiretls", requiretls: "enforce" });
    expect(mailFrom(supporting)).toEndWith(" REQUIRETLS");
  });

  test("a server without REQUIRETLS is never sent the message", async () => {
    const before = lacking.sessions.length;
    const r = await send({ domain: "signed.test", mx: lacking });
    expect(r.recipients[0]).toMatchObject({ status: "bounced", enhanced: "5.7.30" });
    expect(lacking.sessions.length).toBe(before + 1);
    expect(mailFrom(lacking)).toBeNull();
    const commands = () => lacking.sessions.at(-1)?.commands ?? [];
    for (let i = 0; i < 50 && commands().at(-1) !== "QUIT"; i++) await Bun.sleep(10);
    expect(commands().at(-1)).toBe("QUIT");
  });

  test("an unsigned MX without MTA-STS bounces before connecting", async () => {
    const before = supporting.sessions.length;
    const r = await send({ domain: "plain.test", mx: supporting });
    expect(r.recipients[0]).toMatchObject({ status: "bounced", enhanced: "5.7.30" });
    expect(r.sessions).toHaveLength(0);
    expect(supporting.sessions.length).toBe(before);
  });

  test("an enforced MTA-STS policy is a secure lookup too", async () => {
    const r = await send({ domain: "plain.test", mx: supporting, sts: true });
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(mailFrom(supporting)).toEndWith(" REQUIRETLS");
  });

  test("a certificate that cannot be verified defers", async () => {
    const r = await send({ domain: "signed.test", mx: supporting, ca: false });
    expect(r.recipients[0]).toMatchObject({ status: "deferred", enhanced: "4.7.5" });
  });

  test("relaxed: verified TLS is enough; REQUIRETLS is sent only where supported", async () => {
    const plain = await send({ domain: "plain.test", mx: lacking, mode: "relaxed" });
    expect(plain.recipients[0]?.status).toBe("delivered");
    expect(mailFrom(lacking)).not.toContain("REQUIRETLS");
    const ok = await send({ domain: "plain.test", mx: supporting, mode: "relaxed" });
    expect(ok.recipients[0]?.status).toBe("delivered");
    expect(mailFrom(supporting)).toEndWith(" REQUIRETLS");
    const bad = await send({ domain: "plain.test", mx: lacking, mode: "relaxed", ca: false });
    expect(bad.recipients[0]?.status).toBe("deferred");
  });

  test("without require_tls the option is never sent", async () => {
    const r = await send({ domain: "signed.test", mx: supporting, requireTls: false });
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(mailFrom(supporting)).not.toContain("REQUIRETLS");
  });
});

describe("TLS-Required: No", () => {
  test("the recipient's DANE and MTA-STS policies are ignored", async () => {
    const strict = await send({ domain: "pinned.test", mx: lacking, requireTls: false });
    expect(strict.recipients[0]?.status).toBe("deferred");
    const r = await send({
      domain: "pinned.test",
      mx: lacking,
      requireTls: false,
      headers: "TLS-Required: No\r\n",
    });
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.policy?.rule).toBe("tls-optional");
    expect(lacking.sessions.at(-1)?.tls).toBe(true);
  });

  test("require_tls wins over the header", async () => {
    const r = await send({ domain: "plain.test", mx: lacking, headers: "TLS-Required: No\r\n" });
    expect(r.recipients[0]?.status).toBe("bounced");
  });
});
