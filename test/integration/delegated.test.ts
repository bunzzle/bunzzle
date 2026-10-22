import { afterAll, beforeAll, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { zoneLabel } from "../../src/domains/delegated.ts";
import { RpcClient } from "../../src/ipc/rpc.ts";
import { verifyDkim } from "../support/dkim-verify.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const NS_ZONE = "dz.mail.test";
const OWNER = `${zoneLabel("shop.test")}.${NS_ZONE}`;
const zone: Zone = {};
let dns: FakeDns;
let served: Served;
let token: string;

interface DomainView {
  mode: string;
  status: string;
  records: { record: string; type: string; name: string; value: string; status: string }[];
}

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

async function savedZone(name: string): Promise<{ name: string; value: string }[]> {
  const path = `${served.dir}/data/ns-zone.json`;
  const end = Date.now() + 20_000;
  while (Date.now() < end) {
    const file = Bun.file(path);
    if (await file.exists()) {
      const z = (await file.json()) as { records: { name: string; value: string }[] };
      if (z.records.some((r) => r.name === name)) return z.records;
    }
    await Bun.sleep(200);
  }
  throw new Error(`${name} never reached the saved zone`);
}

beforeAll(async () => {
  dns = await startFakeDns(zone);
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_SOURCE_IPS: "127.0.0.1",
    BUNZZLE_RETRY_SCALE: "0.001",
    BUNZZLE_NS_ZONE: NS_ZONE,
    BUNZZLE_NS_NAMES: "ns1.mail.test",
    BUNZZLE_NS_LISTEN: "127.0.0.1",
    BUNZZLE_NS_PORT: "0",
  });
  token =
    (await cli("keys", "create", "--name", "t", "--scope", "full")).stdout
      .trim()
      .split("\n")
      .at(-1) ?? "";
}, 60_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
});

test("a delegated domain verifies through CNAMEs and signs with the keys the zone serves", async () => {
  const added = await api("/domains", {
    method: "POST",
    body: JSON.stringify({ name: "shop.test", mode: "delegated" }),
  });
  expect(added.status).toBe(200);
  const d = (await added.json()) as DomainView;
  expect(d.mode).toBe("delegated");
  expect(d.status).toBe("pending");
  const dkim = d.records.filter((r) => r.record === "DKIM");
  expect(dkim.map((r) => [r.type, r.name, r.value])).toEqual(
    ["bza-r", "bzb-r", "bza-e", "bzb-e"].map((s) => [
      "CNAME",
      `${s}._domainkey.shop.test`,
      `${s}.${OWNER}`,
    ]),
  );
  expect(d.records.find((r) => r.record === "SPF")?.value).toBe(
    `v=spf1 include:_spf.${NS_ZONE} ~all`,
  );

  const records = await savedZone(`bza-r.${OWNER}`);
  expect(records.find((r) => r.name === `_spf.${NS_ZONE}`)?.value).toBe(
    "v=spf1 ip4:127.0.0.1 ~all",
  );
  expect(records.some((r) => r.name === `bzb-r.${OWNER}`)).toBe(false);

  const [first, ...rest] = dkim;
  zone[first?.name ?? ""] = { CNAME: "dkim.shop.test" };
  zone["dkim.shop.test"] = { CNAME: first?.value ?? "" };
  for (const r of rest) zone[r.name] = { CNAME: r.value };
  const verified = (await (
    await api("/domains/shop.test/verify", { method: "POST" })
  ).json()) as DomainView;
  expect(verified.status).toBe("verified");
  expect(verified.records.find((r) => r.name === first?.name)?.status).toBe("verified");

  const shown = await cli("domains", "show", "shop.test");
  expect(shown.stdout).toContain(`CNAME  bza-r._domainkey.shop.test`);

  const signer = new RpcClient(`${served.dir}/run/signer.sock`);
  const signed = await signer.call<string>("signCanary", { domain: "shop.test", which: "active" });
  signer.close();
  expect(signed).toMatch(/s=bza-r;/);
  expect(signed).toMatch(/s=bza-e;/);
  const keys = Object.fromEntries(
    records
      .filter((r) => r.name.endsWith(`.${OWNER}`) && r.value.startsWith("v=DKIM1"))
      .map((r) => [
        r.name.split(".")[0],
        {
          algorithm: r.value.includes("k=rsa")
            ? ("rsa-sha256" as const)
            : ("ed25519-sha256" as const),
          key: Uint8Array.fromBase64(/p=([^;\s]+)/.exec(r.value)?.[1] ?? ""),
        },
      ]),
  );
  const verdicts = await verifyDkim(signed, keys);
  expect(verdicts.length).toBe(2);
  expect(verdicts.every((v) => v.ok)).toBe(true);
}, 60_000);

test("the CLI adds a delegated domain; a record domain stays in records mode", async () => {
  const delegated = await cli("domains", "add", "cli.test", "--delegated");
  expect(delegated.code).toBe(0);
  expect(delegated.stdout).toContain("CNAME  bzb-e._domainkey.cli.test");
  const plain = (await (
    await api("/domains", { method: "POST", body: JSON.stringify({ name: "plain.test" }) })
  ).json()) as DomainView;
  expect(plain.mode).toBe("records");
  expect(plain.records.some((r) => r.type === "CNAME")).toBe(false);
});

test("a verified delegated domain switches to records through PATCH; the CLI waits for the rotation", async () => {
  const bad = await api("/domains/shop.test", {
    method: "PATCH",
    body: JSON.stringify({ mode: "zone" }),
  });
  expect(bad.status).toBe(422);

  const res = await api("/domains/shop.test", {
    method: "PATCH",
    body: JSON.stringify({ mode: "records" }),
  });
  expect(res.status).toBe(200);
  const d = (await res.json()) as DomainView;
  expect(d.mode).toBe("records");
  expect(d.status).toBe("verified");
  expect(d.records.filter((r) => r.record === "DKIM_NEXT").map((r) => r.type)).toEqual([
    "TXT",
    "TXT",
  ]);
  expect(d.records.filter((r) => r.record === "DKIM" && r.type === "CNAME").length).toBe(4);

  const again = await cli("domains", "mode", "shop.test", "delegated");
  expect(again.code).not.toBe(0);
  expect(again.stderr).toContain("still running");
  expect((await cli("domains", "mode", "shop.test")).code).not.toBe(0);
});
