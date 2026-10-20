import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let live: string;
let testKey: string;

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
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

async function newKey(...flags: string[]) {
  const r = await cli("keys", "create", "--name", "t", "--scope", "full", ...flags);
  if (r.code !== 0) throw new Error(`keys create failed: ${r.stderr}`);
  return { out: r.stdout, token: (r.stdout.trim().split("\n").at(-1) ?? "").trim() };
}

const api = (path: string, token: string, init: RequestInit = {}) =>
  fetch(`${served.url}${path}`, {
    ...init,
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
  });

const send = (token: string, to: string[], from = "hello@acme.test") =>
  api("/emails", token, {
    method: "POST",
    body: JSON.stringify({ from, to, subject: "Hi", text: "Hi" }),
  });

interface View {
  recipients: { email: string; status: string }[];
  events: { type: string }[];
  attempts: unknown[];
}

async function settle(token: string, id: string, done: (v: View) => boolean): Promise<View> {
  let v = (await (await api(`/emails/${id}`, token)).json()) as View;
  for (let i = 0; i < 150 && !done(v); i++) {
    await Bun.sleep(100);
    v = (await (await api(`/emails/${id}`, token)).json()) as View;
  }
  return v;
}

const delivered = () => mx.sessions.reduce((n, s) => n + s.messages.length, 0);

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  live = (await newKey()).token;
  const created = await newKey("--test");
  expect(created.out).toContain("Created test API key");
  testKey = created.token;
  expect((await cli("domains", "add", "acme.test")).code).toBe(0);
}, 30_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

describe("test mode", () => {
  test("a test key sends from a domain that is not verified yet; nothing leaves the server", async () => {
    expect((await send(live, ["user@example.test"])).status).toBe(403);
    const r = await send(testKey, ["user@example.test"]);
    expect(r.status).toBe(200);
    const { id } = (await r.json()) as { id: string };
    const v = await settle(testKey, id, (x) => x.recipients[0]?.status === "delivered");
    expect(v.recipients).toEqual([
      expect.objectContaining({ email: "user@example.test", status: "delivered" }),
    ]);
    expect(delivered()).toBe(0);
    const keys = await cli("keys", "list");
    expect(keys.stdout).toMatch(/ test +full {2}t/);
  });

  test("an unregistered domain is refused even in test mode", async () => {
    const r = await send(testKey, ["user@example.test"], "hello@other.test");
    expect(r.status).toBe(403);
  });
});

describe("simulator addresses", () => {
  test("delivered, bounced, deferred, complained and suppressed, with the usual events", async () => {
    const r = await send(testKey, [
      "delivered@simulator.test",
      "bounced@simulator.test",
      "deferred@simulator.test",
      "complained@simulator.test",
      "suppressed@simulator.test",
    ]);
    expect(r.status).toBe(200);
    const { id } = (await r.json()) as { id: string };
    const v = await settle(
      testKey,
      id,
      (x) =>
        x.recipients.find((p) => p.email === "deferred@simulator.test")?.status === "delivered" &&
        x.events.some((e) => e.type === "complained"),
    );
    const status = Object.fromEntries(v.recipients.map((p) => [p.email, p.status]));
    expect(status).toEqual({
      "delivered@simulator.test": "delivered",
      "bounced@simulator.test": "bounced",
      "deferred@simulator.test": "delivered",
      "complained@simulator.test": "delivered",
      "suppressed@simulator.test": "suppressed",
    });
    expect(v.events.map((e) => e.type)).toEqual(
      expect.arrayContaining(["suppressed", "address_suppressed", "complained"]),
    );
    const results = (v.attempts as { results: { email: string; status: string }[] }[]).flatMap(
      (a) => a.results.map((x) => `${x.email} ${x.status}`),
    );
    expect(results).toEqual(
      expect.arrayContaining([
        "deferred@simulator.test deferred",
        "deferred@simulator.test delivered",
        "bounced@simulator.test bounced",
      ]),
    );
    const list = (await (await api("/suppressions", testKey)).json()) as {
      data: { email: string; reason: string }[];
    };
    const reasons = Object.fromEntries(list.data.map((s) => [s.email, s.reason]));
    expect(reasons["bounced@simulator.test"]).toBe("hard-bounce");
    expect(reasons["complained@simulator.test"]).toBe("complaint");
    expect(delivered()).toBe(0);
  }, 30_000);
});
