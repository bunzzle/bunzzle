import { Database } from "bun:sqlite";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
  "1.0.0.127.in-addr.arpa": { PTR: "out.bunzzle.test" },
  "out.bunzzle.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let token: string;

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

const api = (path: string, init: RequestInit = {}) =>
  fetch(`${served.url}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  });

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_SOURCE_IPS: "127.0.0.1=acme",
    BUNZZLE_ESTABLISHED_IPS: "127.0.0.1",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  token =
    (await cli("keys", "create", "--name", "t", "--scope", "full")).stdout
      .trim()
      .split("\n")
      .at(-1) ?? "";
  await cli("domains", "add", "acme.test");
  const d = (await (await api("/domains/acme.test")).json()) as {
    records: { record: string; name: string; value: string }[];
  };
  for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
  await cli("domains", "verify", "acme.test");
}, 60_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

test("a domain tied to a pool records it on its email; unknown pools are refused", async () => {
  const bad = await api("/domains/acme.test", {
    method: "PATCH",
    body: JSON.stringify({ ip_pool: "missing" }),
  });
  expect(bad.status).toBe(422);
  expect(((await bad.json()) as { message: string }).message).toContain(
    "pools in BUNZZLE_SOURCE_IPS: acme",
  );
  const ok = await api("/domains/acme.test", {
    method: "PATCH",
    body: JSON.stringify({ ip_pool: "acme" }),
  });
  expect(await ok.json()).toEqual({ name: "acme.test", ip_pool: "acme" });
  expect(((await (await api("/domains/acme.test")).json()) as { ip_pool: string }).ip_pool).toBe(
    "acme",
  );
  expect(
    (
      await api("/domains/none.test", {
        method: "PATCH",
        body: JSON.stringify({ ip_pool: "acme" }),
      })
    ).status,
  ).toBe(404);

  const r = await api("/emails", {
    method: "POST",
    body: JSON.stringify({
      from: "hello@acme.test",
      to: ["user@example.test"],
      subject: "x",
      text: "x",
    }),
  });
  const { id } = (await r.json()) as { id: string };
  const db = new Database(`${served.dir}/data/bunzzle.db`, { readonly: true });
  const row = db.query("SELECT metadata FROM messages WHERE id = ?").get(id) as {
    metadata: string;
  };
  db.close();
  expect(JSON.parse(row.metadata).pool).toBe("acme");

  const doctor = await cli("doctor");
  expect(doctor.stdout).toContain("acme.test IP pool: sends only from the pool acme: 127.0.0.1");
  expect((await cli("domains", "pool", "acme.test", "none")).stdout).toContain(
    "uses the shared IPs again",
  );
  expect((await cli("keys", "create", "--name", "k", "--pool", "nowhere")).code).not.toBe(0);
  expect((await cli("keys", "create", "--name", "k", "--pool", "acme")).code).toBe(0);
}, 60_000);

test("pool rules: the CLI adds server rules, the API adds project rules; bad targets are refused", async () => {
  const added = await cli("pools", "rules", "add", "Google", "acme");
  expect(added.code).toBe(0);
  expect(added.stdout).toMatch(/^\S+ {2}mail for google goes out from acme/);
  const id = added.stdout.split(" ")[0] as string;
  expect((await cli("pools", "rules")).stdout).toContain(`${id}  google`);
  expect((await cli("pools", "rules", "add", "google", "acme")).stderr).toContain(
    "there is already a rule for google",
  );
  expect((await cli("pools", "rules", "add", "example.org", "relay")).stderr).toContain(
    "this server has no BUNZZLE_RELAY_HOST",
  );
  expect((await cli("pools", "rules", "add", "example.org", "nowhere")).stderr).toContain(
    "no source IP is in the pool nowhere",
  );

  const project = await api("/pool-rules", {
    method: "POST",
    body: JSON.stringify({ match: "Example.ORG", pool: "acme" }),
  });
  expect(await project.json()).toMatchObject({
    match: "example.org",
    pool: "acme",
    scope: "project",
  });
  const relay = await api("/pool-rules", {
    method: "POST",
    body: JSON.stringify({ match: "example.net", pool: "relay" }),
  });
  expect(relay.status).toBe(422);
  const list = (await (await api("/pool-rules")).json()) as { data: { match: string }[] };
  expect(list.data.map((r) => r.match)).toEqual(["example.org"]);

  expect((await cli("pools", "rules", "remove", id)).stdout).toBe(`Removed ${id}.\n`);
  expect((await cli("pools", "rules")).stdout).toContain("No pool rules");
}, 60_000);
