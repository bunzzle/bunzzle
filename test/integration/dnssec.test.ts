import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { spkiOf } from "../../src/asn1/der.ts";
import { localTransport } from "../../src/delivery/transport.ts";
import { createResolver, type Resolver } from "../../src/dns/resolver.ts";
import { nameToWire, RRType } from "../../src/dns/wire.ts";
import { ownValidation } from "../../src/dnssec/resolver.ts";
import { a, record } from "../support/dnssec.ts";
import { type TestWorld, world } from "../support/dnssec-world.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const TLS = `${import.meta.dir}/../fixtures/tls`;
let w: TestWorld;
let dns: FakeDns;
let mx: FakeMx;

const mxRecord = (domain: string, host: string) =>
  record(domain, RRType.MX, Uint8Array.from([0, 10, ...nameToWire(host)]));
const tlsa = (host: string, data: Uint8Array) =>
  record(`_25._tcp.${host}`, RRType.TLSA, Uint8Array.from([3, 1, 1, ...data]));

beforeAll(async () => {
  const pem = await Bun.file(`${TLS}/mx.pem`).text();
  const der = Uint8Array.fromBase64(pem.replace(/-----[^-]+-----|\s/g, ""));
  const h = new Bun.CryptoHasher("sha256");
  h.update(spkiOf(der));
  const spki = new Uint8Array(h.digest());
  w = await world(
    [[""], ["test"], ["example.test"], ["plain.example.test", { signed: false }]],
    [
      mxRecord("example.test", "mx.example.test"),
      a("mx.example.test", "127.0.0.1"),
      tlsa("mx.example.test", spki),
      mxRecord("wrong.example.test", "mx2.example.test"),
      a("mx2.example.test", "127.0.0.1"),
      tlsa("mx2.example.test", new Uint8Array(32)),
      mxRecord("plain.example.test", "mx.plain.example.test"),
      a("mx.plain.example.test", "127.0.0.1"),
    ],
  );
  dns = await startFakeDns(w);
  mx = startFakeMx();
});

afterAll(() => {
  dns.stop();
  mx.stop();
});

async function validating(): Promise<Resolver> {
  const base = createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] });
  const own = await ownValidation(
    (n, t) => (base.message as NonNullable<Resolver["message"]>)(n, t),
    {
      probe: "mx.example.test",
      anchors: w.anchors,
    },
  );
  if (!("resolver" in own)) throw new Error(own.problem);
  return own.resolver;
}

async function deliver(domain: string) {
  const t = localTransport(
    {
      resolver: await validating(),
      ehloName: "out.bunzzle.test",
      port: mx.port,
      allowPrivate: true,
      tlsCa: TEST_CA,
      timeouts: { greeting: 2_000, quit: 200 },
      dane: true,
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

describe("own DNSSEC validation over the network", () => {
  test("the start-up probe validates a signed name", async () => {
    expect(await validating()).toBeDefined();
  });

  test("a large signed denial comes over TCP and is proven", async () => {
    const r = await (await validating()).query("nothing.example.test", "A");
    expect(r).toMatchObject({ rcode: 3, authenticated: true });
    expect(dns.queries.some((q) => q.name === "nothing.example.test" && q.tcp)).toBe(true);
  });

  test("a server that strips signatures fails the probe", async () => {
    w.overrides.set(`mx.example.test|${RRType.A}`, (m) => ({
      ...m,
      answers: m.answers.filter((r) => r.type !== "RRSIG"),
    }));
    await expect(validating()).rejects.toThrow("do not return what DNSSEC needs");
    w.overrides.clear();
  });

  test("DANE works without a local validating resolver", async () => {
    const r = await deliver("example.test");
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.sessions[0]?.tls.status).toBe("dane");
  });

  test("a TLSA record that does not match defers", async () => {
    const r = await deliver("wrong.example.test");
    expect(r.recipients[0]?.status).toBe("deferred");
    expect(r.sessions[0]?.error).toContain("DANE");
  });

  test("a forged MX answer defers with the DNSSEC reason", async () => {
    w.overrides.set(`example.test|${RRType.MX}`, (m) => ({
      ...m,
      answers: m.answers.map((x) =>
        x.type === "MX" ? mxRecord("example.test", "evil.example.test") : x,
      ),
    }));
    const r = await deliver("example.test");
    w.overrides.clear();
    expect(r.recipients[0]?.status).toBe("deferred");
    expect(r.recipients[0]?.reply).toContain("failed DNSSEC");
  });

  test("an unsigned zone is delivered as before, without DANE", async () => {
    const r = await deliver("plain.example.test");
    expect(r.recipients[0]?.status).toBe("delivered");
    expect(r.policy?.rule).not.toBe("dane");
  });
});
