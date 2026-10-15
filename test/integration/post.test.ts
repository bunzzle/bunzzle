import { afterAll, beforeAll, expect, test } from "bun:test";
import { createResolver } from "../../src/dns/resolver.ts";
import { guardedPost } from "../../src/net/post.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { TEST_CA } from "../support/fake-mx.ts";

const TLS_DIR = `${import.meta.dir}/../fixtures/tls`;
let dns: FakeDns;
let http: ReturnType<typeof Bun.serve>;
let https: ReturnType<typeof Bun.serve>;
const seen: { headers: Record<string, string>; body: string }[] = [];

beforeAll(async () => {
  dns = await startFakeDns({
    "hooks.example.test": { A: ["127.0.0.1"] },
    "mx.example.test": { A: ["127.0.0.1"] },
    "rebind.example.test": { A: ["10.0.0.5"] },
  });
  const fetch = async (req: Request) => {
    if (new URL(req.url).pathname === "/moved") {
      return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } });
    }
    seen.push({ headers: Object.fromEntries(req.headers), body: await req.text() });
    return new Response("ok");
  };
  http = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch });
  https = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    tls: {
      key: Bun.file(`${TLS_DIR}/mx.key`),
      cert: Bun.file(`${TLS_DIR}/mx.pem`),
    },
    fetch,
  });
});

afterAll(() => {
  http.stop(true);
  https.stop(true);
  dns.stop();
});

const resolver = () => createResolver({ servers: [{ host: "127.0.0.1", port: dns.port }] });

test("private and loopback destinations are refused by default", async () => {
  const r = await guardedPost(`http://hooks.example.test:${http.port}/x`, {}, "{}", {
    resolver: resolver(),
  });
  expect(r).toEqual({
    ok: false,
    error: "hooks.example.test points to a private or forbidden network",
  });
  const rebind = await guardedPost("http://rebind.example.test/x", {}, "{}", {
    resolver: resolver(),
  });
  expect(rebind.ok).toBe(false);
  const metadata = await guardedPost("http://169.254.169.254/latest", {}, "{}", {
    resolver: resolver(),
  });
  expect(metadata.ok).toBe(false);
});

test("posts JSON with our headers when allowed", async () => {
  const r = await guardedPost(
    `http://hooks.example.test:${http.port}/hook?x=1`,
    { "webhook-id": "msg_1" },
    '{"a":1}',
    { resolver: resolver(), allowPrivate: true },
  );
  expect(r).toEqual({ ok: true, status: 200 });
  expect(seen.at(-1)).toMatchObject({ body: '{"a":1}' });
  expect(seen.at(-1)?.headers["webhook-id"]).toBe("msg_1");
  expect(seen.at(-1)?.headers["content-type"]).toBe("application/json");
});

test("https connects to the vetted IP but still checks the certificate name", async () => {
  const ok = await guardedPost(`https://mx.example.test:${https.port}/hook`, {}, "{}", {
    resolver: resolver(),
    allowPrivate: true,
    ca: TEST_CA,
  });
  expect(ok).toEqual({ ok: true, status: 200 });
  const wrongName = await guardedPost(`https://hooks.example.test:${https.port}/hook`, {}, "{}", {
    resolver: resolver(),
    allowPrivate: true,
    ca: TEST_CA,
  });
  expect(wrongName.ok).toBe(false);
});

test("redirects are not followed", async () => {
  const r = await guardedPost(`http://hooks.example.test:${http.port}/moved`, {}, "{}", {
    resolver: resolver(),
    allowPrivate: true,
  });
  expect(r).toEqual({ ok: true, status: 302 });
});
