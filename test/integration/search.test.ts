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
let token: string;
let testKey: string;
const sent: Record<string, string> = {};
const of = (...names: string[]) => names.map((n) => sent[n] as string);

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
  return { stdout, code };
}

const api = (path: string, init: RequestInit & { key?: string } = {}) =>
  fetch(`${served.url}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${init.key ?? token}`, "content-type": "application/json" },
  });

async function send(
  name: string,
  to: string,
  tags: { name: string; value: string }[],
  key = token,
) {
  const r = await api("/emails", {
    method: "POST",
    key,
    body: JSON.stringify({ from: "hello@acme.test", to: [to], subject: name, text: "x", tags }),
  });
  expect(r.status).toBe(200);
  sent[name] = ((await r.json()) as { id: string }).id;
}

interface Page {
  data: { id: string; last_event: string; to: string[] }[];
  next_cursor: string | null;
}
const list = async (q: string) => (await (await api(`/emails?${q}`)).json()) as Page;
const ids = async (q: string) => (await list(q)).data.map((e) => e.id);

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
  token =
    (await cli("keys", "create", "--name", "t", "--scope", "full", "--rate-limit", "1000")).stdout
      .trim()
      .split("\n")
      .at(-1) ?? "";
  testKey =
    (await cli("keys", "create", "--name", "dev", "--scope", "full", "--test")).stdout
      .trim()
      .split("\n")
      .at(-1) ?? "";
  await cli("domains", "add", "acme.test");
  const d = (await (await api("/domains/acme.test")).json()) as {
    records: { record: string; name: string; value: string }[];
  };
  for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
  expect((await cli("domains", "verify", "acme.test")).stdout).toContain("verified");

  await send("a", "one@example.test", [{ name: "kind", value: "login" }]);
  await send("b", "two@example.test", [{ name: "kind", value: "news" }]);
  await send("c", "bounced@simulator.test", [{ name: "kind", value: "login" }]);
  await send("d", "complained@simulator.test", []);
  await send("e", "one@example.test", [{ name: "kind", value: "login" }]);
  await send("t", "one@example.test", [{ name: "kind", value: "login" }], testKey);
  for (let i = 0; i < 100; i++) {
    const page = await list("limit=100");
    const done = page.data.every((e) => ["delivered", "bounced"].includes(e.last_event));
    const complained = (await (await api(`/emails/${sent["d"]}`)).json()) as {
      events: { type: string }[];
    };
    if (done && complained.events.some((e) => e.type === "complained")) break;
    await Bun.sleep(100);
  }
}, 60_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

describe("GET /emails", () => {
  test("newest first, with filters for recipient, status, tag and sender domain", async () => {
    expect(await ids("limit=100")).toEqual(of("t", "e", "d", "c", "b", "a"));
    expect(await ids("to=ONE@example.test")).toEqual(of("t", "e", "a"));
    expect(await ids("status=bounced")).toEqual(of("c"));
    expect(await ids("status=delivered&to=two@example.test")).toEqual(of("b"));
    expect(await ids("tag=kind:login")).toEqual(of("t", "e", "c", "a"));
    expect(await ids("tag=kind:login&status=bounced")).toEqual(of("c"));
    expect(await ids("domain=acme.test&limit=1")).toEqual(of("t"));
    expect(await ids("domain=other.test")).toEqual([]);
  });

  test("cursor paging and time ranges", async () => {
    const first = await list("limit=4");
    expect(first.data).toHaveLength(4);
    const second = await list(`limit=4&cursor=${first.next_cursor}`);
    expect([...first.data, ...second.data].map((e) => e.id)).toEqual(
      of("t", "e", "d", "c", "b", "a"),
    );
    expect(second.next_cursor).toBeNull();
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(await ids(`since=${future}`)).toEqual([]);
    expect(await ids(`until=${future}&limit=1`)).toEqual(of("t"));
    expect(await ids(`until=2001-01-01T00:00:00Z`)).toEqual([]);
  });

  test("bad filters are refused", async () => {
    expect((await api("/emails?status=lost")).status).toBe(422);
    expect((await api("/emails?limit=500")).status).toBe(422);
    expect((await api("/emails?since=yesterday")).status).toBe(422);
  });
});

describe("GET /stats and bunzzle stats", () => {
  test("counts per day, by tag and domain; test-mode email is left out", async () => {
    const today = new Date().toISOString().slice(0, 10);
    const all = (await (await api("/stats")).json()) as {
      totals: Record<string, number>;
      data: { day: string }[];
    };
    expect(all.data).toHaveLength(7);
    expect(all.data.at(-1)?.day).toBe(today);
    expect(all.totals).toMatchObject({ sent: 5, delivered: 4, bounced: 1, complained: 1 });
    const login = (await (await api("/stats?tag=kind:login")).json()) as {
      totals: Record<string, number>;
    };
    expect(login.totals).toMatchObject({ sent: 3, delivered: 2, bounced: 1 });
    const other = (await (
      await api(`/stats?domain=other.test&since=${today}&until=${today}`)
    ).json()) as {
      totals: Record<string, number>;
    };
    expect(other.totals["sent"]).toBe(0);
    expect((await api("/stats?since=2026-01-01&until=2020-01-01")).status).toBe(422);
    expect((await api("/stats?until=yesterday")).status).toBe(422);
    expect((await api("/stats?since=2026-13-45")).status).toBe(422);
    const out = await cli("stats");
    expect(out.code).toBe(0);
    expect(out.stdout).toMatch(/total\s+5\s+4/);
    const emails = await cli("emails", "list", "--status", "bounced");
    expect(emails.stdout).toContain(sent["c"] as string);
  });
});
