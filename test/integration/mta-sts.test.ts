import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { localTransport } from "../../src/delivery/transport.ts";
import { createResolver } from "../../src/dns/resolver.ts";
import { guardedRequest } from "../../src/net/request.ts";
import { mxAllowed, parsePolicy, StsCache } from "../../src/smtp/mta-sts.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const TLS = `${import.meta.dir}/../fixtures/tls`;
const STS_CA = await Bun.file(`${TLS}/sts-ca.pem`).text();
let dns: FakeDns;
let mx: FakeMx;
let web: ReturnType<typeof Bun.serve>;
const policies: Record<string, string> = {
  "mta-sts.strict.test": "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: 86400\n",
  "mta-sts.testing.test": "version: STSv1\nmode: testing\nmx: other.example.test\nmax_age: 86400\n",
  "mta-sts.example.test": "version: STSv1\nmode: enforce\nmx: *.elsewhere.test\nmax_age: 86400\n",
};
let fetches = 0;

beforeAll(async () => {
  web = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    tls: { key: Bun.file(`${TLS}/sts.key`), cert: Bun.file(`${TLS}/sts.pem`) },
    fetch(req) {
      fetches++;
      const host = new URL(req.url).hostname;
      const body = policies[host];
      return body
        ? new Response(body, { headers: { "content-type": "text/plain" } })
        : new Response("no", { status: 404 });
    },
  });
  const zone: Zone = {
    "mx.example.test": { A: ["127.0.0.1"] },
    "mta-sts.strict.test": { A: ["127.0.0.1"] },
    "mta-sts.testing.test": { A: ["127.0.0.1"] },
    "mta-sts.example.test": { A: ["127.0.0.1"] },
    "_mta-sts.strict.test": { TXT: ["v=STSv1; id=20261015"] },
    "_mta-sts.testing.test": { TXT: ["v=STSv1; id=1"] },
    "_mta-sts.example.test": { TXT: ["v=STSv1; id=7"] },
    "strict.test": { MX: [[10, "mx.example.test"]] },
    "testing.test": { MX: [[10, "mx.example.test"]] },
    "example.test": { MX: [[10, "mx.example.test"]] },
    "plain.test": { MX: [[10, "mx.example.test"]] },
  };
  dns = await startFakeDns(zone);
  mx = startFakeMx();
});

afterAll(() => {
  web.stop(true);
  dns.stop();
  mx.stop();
});

const resolver = () => createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] });

function cache(now = () => Date.now()) {
  const r = resolver();
  return new StsCache(
    r,
    async (url) => {
      const u = new URL(url);
      const res = await guardedRequest(
        { method: "GET", url: `https://${u.hostname}:${web.port}${u.pathname}` },
        { resolver: r, allowPrivate: true, ca: STS_CA },
      );
      return res.ok
        ? { status: res.status, type: res.headers.get("content-type") ?? "", body: res.body }
        : null;
    },
    now,
  );
}

describe("MTA-STS policies (D2)", () => {
  test("parsing and MX matching (RFC 8461)", () => {
    expect(parsePolicy(policies["mta-sts.strict.test"] as string)).toEqual({
      mode: "enforce",
      mx: ["mx.example.test"],
      maxAge: 86400,
    });
    expect(parsePolicy("version: STSv1\nmode: enforce\nmax_age: 10\n")).toBeNull();
    expect(parsePolicy("version: STSv2\nmode: none\nmax_age: 10\n")).toBeNull();
    expect(mxAllowed("mx1.google.com", ["*.google.com"])).toBe(true);
    expect(mxAllowed("a.b.google.com", ["*.google.com"])).toBe(false);
    expect(mxAllowed("google.com", ["*.google.com"])).toBe(false);
    expect(mxAllowed("MX.Example.Test.", ["mx.example.test"])).toBe(true);
  });

  test("fetched over verified HTTPS, cached by id, absent policies are null", async () => {
    const c = cache();
    const before = fetches;
    expect(await c.policyFor("strict.test")).toMatchObject({ mode: "enforce", id: "20261015" });
    expect(await c.policyFor("strict.test")).toMatchObject({ id: "20261015" });
    expect(fetches).toBe(before + 1);
    expect(await c.policyFor("plain.test")).toBeNull();
  });

  const deliver = async (domain: string) => {
    const c = cache();
    const t = localTransport(
      {
        resolver: resolver(),
        ehloName: "out.bunzzle.test",
        port: mx.port,
        allowPrivate: true,
        tlsCa: TEST_CA,
        timeouts: { greeting: 2_000, quit: 200 },
        sts: (d) => c.policyFor(d),
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
  };

  test("enforce: TLS with a valid certificate is required (rule mta-sts) and the MX must match", async () => {
    const r = await deliver("strict.test");
    expect(r.policy).toEqual({ rule: "mta-sts", required: true });
    expect(r.mtaSts).toMatchObject({ mode: "enforce", id: "20261015" });
    expect(r.sessions[0]?.tls).toMatchObject({ status: "verified", rule: "mta-sts" });
    expect(r.recipients[0]?.status).toBe("delivered");
  });

  test("enforce with no allowed MX: deferred, never sent", async () => {
    const sessions = mx.sessions.length;
    const r = await deliver("example.test");
    expect(r.recipients[0]).toMatchObject({ status: "deferred", enhanced: "4.7.5" });
    expect(r.recipients[0]?.reply).toContain("MTA-STS");
    expect(mx.sessions.length).toBe(sessions);
  });

  test("testing mode is recorded but not enforced", async () => {
    const r = await deliver("testing.test");
    expect(r.policy?.rule).toBe("opportunistic");
    expect(r.mtaSts).toMatchObject({ mode: "testing", id: "1" });
    expect(r.recipients[0]?.status).toBe("delivered");
  });
});
