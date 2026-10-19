import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { spkiOf } from "../../src/asn1/der.ts";
import { localTransport } from "../../src/delivery/transport.ts";
import { localValidatingResolver } from "../../src/dns/dnssec.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import { matches, verifyDane } from "../../src/smtp/dane.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx, TEST_CA } from "../support/fake-mx.ts";
import { type Issued, issue, privateKeyPem, sha256 } from "../support/x509.ts";

const TLS = `${import.meta.dir}/../fixtures/tls`;
const SPKI_SHA256 = "795a214456820593df29ed92563495d5d5d8fad1a050502e4f2488c3a5dc55fd";
const CERT_SHA256 = "ad35386fff9e2eed8a8b8519025967f0bb6d13c79a6ddbfeeb4f71c6a38c1d00";
const WRONG = "00".repeat(32);

let dns: FakeDns;
let mx: FakeMx;
const zone: Zone = {
  "iana.org": { A: ["192.0.2.1"], secure: true },
  "mx.example.test": { A: ["127.0.0.1"], secure: true },
  "good.test": { MX: [[10, "mx.example.test"]], secure: true },
  "_25._tcp.mx.example.test": { TLSA: [[3, 1, 1, SPKI_SHA256]], secure: true },
  "bad.test": { MX: [[10, "mx.bad.test"]], secure: true },
  "mx.bad.test": { A: ["127.0.0.1"], secure: true },
  "_25._tcp.mx.bad.test": { TLSA: [[3, 1, 1, WRONG]], secure: true },
  "unsigned.test": { MX: [[10, "mx.unsigned.test"]] },
  "mx.unsigned.test": { A: ["127.0.0.1"] },
  "_25._tcp.mx.unsigned.test": { TLSA: [[3, 1, 1, WRONG]] },
  "broken.test": { MX: [[10, "mx.broken.test"]], secure: true },
  "mx.broken.test": { A: ["127.0.0.1"], secure: true },
  "_25._tcp.mx.broken.test": { rcode: 2 },
  "unusable.test": { MX: [[10, "mx.unusable.test"]], secure: true },
  "mx.unusable.test": { A: ["127.0.0.1"], secure: true },
  "_25._tcp.mx.unusable.test": { TLSA: [[1, 1, 1, WRONG]], secure: true },
};

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
});

afterAll(() => {
  dns.stop();
  mx.stop();
});

const resolver = () => createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] });

async function deliver(domain: string, dane = true, port = mx.port) {
  const t = localTransport(
    {
      resolver: resolver(),
      ehloName: "out.bunzzle.test",
      port,
      allowPrivate: true,
      tlsCa: TEST_CA,
      timeouts: { greeting: 2_000, quit: 200 },
      dane,
    },
    async () => ({ data: "From: a@bunzzle.test\r\nSubject: x\r\n\r\nx\r\n", bounceToken: "t" }),
  );
  return t.deliver({
    key: "k",
    recall: null,
    messageId: "m",
    domain,
    destination: await t.lookup(domain),
    from: "a@bunzzle.test",
    recipients: [`x@${domain}`],
    smtpUtf8: false,
    requireTls: false,
    body: { epoch: 1, wrapped: new Uint8Array(), body: new Uint8Array() },
  });
}

describe("DANE", () => {
  test("TLSA matching against the certificate and its public key", async () => {
    const pem = await Bun.file(`${TLS}/mx.pem`).text();
    const der = Uint8Array.fromBase64(pem.replace(/-----[^-]+-----|\s/g, ""));
    const hash = (data: Uint8Array) => {
      const h = new Bun.CryptoHasher("sha256");
      h.update(data);
      return new Uint8Array(h.digest()).toHex();
    };
    expect(hash(spkiOf(der))).toBe(SPKI_SHA256);
    const rec = (selector: number, matching: number, hex: string) => ({
      usage: 3,
      selector,
      matching,
      data: Uint8Array.fromHex(hex),
    });
    expect(matches(rec(1, 1, SPKI_SHA256), der)).toBe(true);
    expect(matches(rec(0, 1, CERT_SHA256), der)).toBe(true);
    expect(matches(rec(0, 0, der.toHex()), der)).toBe(true);
    expect(matches(rec(1, 1, WRONG), der)).toBe(false);
    expect(await verifyDane([rec(1, 1, WRONG)], [der], [])).toMatchObject({ ok: false });
    expect(await verifyDane([{ ...rec(1, 1, WRONG), usage: 1 }], [der], [])).toEqual({
      ok: true,
      how: "unauthenticated",
    });
    expect(() => spkiOf(new Uint8Array([0x30, 0x82, 0xff]))).toThrow();
  });

  test("a local resolver that validates DNSSEC is trusted, a remote one never", async () => {
    expect(await localValidatingResolver([{ host: "127.0.0.1", port: dns.port }], resolver())).toBe(
      true,
    );
    expect(await localValidatingResolver([{ host: "192.0.2.53", port: 53 }], resolver())).toBe(
      false,
    );
  });

  test("a matching TLSA record authenticates the server even without a public CA", async () => {
    const r = await deliver("good.test");
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.policy?.rule).toBe("dane");
    expect(r.sessions[0]?.tls.status).toBe("dane");
  });

  test("a certificate that matches no TLSA record is never used", async () => {
    const r = await deliver("bad.test");
    expect(r.recipients[0]?.status).toBe("deferred");
    expect(r.recipients[0]?.enhanced).toBe("4.7.5");
    expect(r.sessions[0]?.error).toContain("DANE");
  });

  test("unsigned zones fall back to the normal rules; a failed TLSA lookup defers", async () => {
    const plain = await deliver("unsigned.test");
    expect(plain.recipients[0]?.status).toBe("delivered");
    expect(plain.policy?.rule).not.toBe("dane");
    const broken = await deliver("broken.test");
    expect(broken.recipients[0]?.status).toBe("deferred");
    expect(broken.sessions[0]?.error).toContain("SERVFAIL");
  });

  test("records present but not usable still require TLS", async () => {
    const r = await deliver("unusable.test");
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.policy).toMatchObject({ rule: "dane", required: true });
    expect(r.sessions[0]?.tls.status).not.toBe("none");
  });

  test("with DANE off, TLSA records are not looked up", async () => {
    const r = await deliver("bad.test", false);
    expect(r.recipients[0]?.status).toBe("delivered");
  });
});

describe("DANE-TA", () => {
  let taMx: FakeMx;
  let namedMx: FakeMx;
  let root: Issued;
  let int: Issued;

  const serve = async (names: string[]) => {
    const leaf = await issue({ name: names[0] as string, issuer: int, dns: names });
    return startFakeMx({
      tls: { key: await privateKeyPem(leaf), cert: leaf.pem + int.pem + root.pem },
    });
  };

  beforeAll(async () => {
    root = await issue({ name: "Test Root", ca: true, keyUsage: "sign-certs" });
    int = await issue({
      name: "Test Intermediate",
      issuer: root,
      ca: true,
      keyUsage: "sign-certs",
    });
    taMx = await serve(["mx.ta.test", "mx.spki.test"]);
    namedMx = await serve(["named.test"]);
    const host = (name: string, tlsa: [number, number, number, string]) => ({
      [name]: { A: ["127.0.0.1"], secure: true },
      [`_25._tcp.${name}`]: { TLSA: [tlsa], secure: true },
    });
    Object.assign(zone, {
      "ta.test": { MX: [[10, "mx.ta.test"]], secure: true },
      ...host("mx.ta.test", [2, 0, 1, sha256(root.der).toHex()]),
      "spki.test": { MX: [[10, "mx.spki.test"]], secure: true },
      ...host("mx.spki.test", [2, 1, 1, sha256(int.spki).toHex()]),
      "named.test": { MX: [[10, "mx.named.test"]], secure: true },
      ...host("mx.named.test", [2, 0, 1, sha256(root.der).toHex()]),
      "stranger.test": { MX: [[10, "mx.stranger.test"]], secure: true },
      ...host("mx.stranger.test", [2, 0, 1, sha256(root.der).toHex()]),
    });
  });

  afterAll(() => {
    taMx.stop();
    namedMx.stop();
  });

  test("a hash of the root authenticates the chain the server sends", async () => {
    const r = await deliver("ta.test", true, taMx.port);
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.sessions[0]?.tls.status).toBe("dane");
  });

  test("a hash of the intermediate key works too", async () => {
    const r = await deliver("spki.test", true, taMx.port);
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.sessions[0]?.tls.status).toBe("dane");
  });

  test("the recipient domain is an accepted name", async () => {
    const r = await deliver("named.test", true, namedMx.port);
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.sessions[0]?.tls.status).toBe("dane");
  });

  test("a certificate for another name is never used", async () => {
    const r = await deliver("stranger.test", true, taMx.port);
    expect(r.recipients[0]?.status).toBe("deferred");
    expect(r.recipients[0]?.enhanced).toBe("4.7.5");
    expect(r.sessions[0]?.error).toContain("match none of mx.stranger.test, stranger.test");
  });
});
