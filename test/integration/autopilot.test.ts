import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
  "1.0.0.127.in-addr.arpa": { PTR: "mail.bunzzle.test" },
  "mail.bunzzle.test": { A: ["127.0.0.1"] },
};
interface CfRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  priority?: number;
}
const cfRecords: CfRecord[] = [];
let cf: ReturnType<typeof Bun.serve>;
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let token: string;

function syncZone(name: string) {
  const entry = { ...(zone[name] ?? {}) };
  const txt = cfRecords.filter((r) => r.name === name && r.type === "TXT").map((r) => r.content);
  const mxs = cfRecords
    .filter((r) => r.name === name && r.type === "MX")
    .map((r) => [r.priority ?? 10, r.content] as [number, string]);
  if (txt.length) entry.TXT = txt;
  else delete entry.TXT;
  if (mxs.length) entry.MX = mxs;
  zone[name] = entry;
}

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "" },
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

const send = (extra: Record<string, unknown> = {}) =>
  fetch(`${served.url}/emails`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({
      from: "Acme <news@acme.test>",
      to: ["reader@example.test"],
      subject: "Hi",
      text: "Hello",
      ...extra,
    }),
  });

beforeAll(async () => {
  cf = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      if (req.headers.get("authorization") !== "Bearer cf-test") {
        return Response.json(
          { success: false, errors: [{ message: "bad token" }] },
          { status: 403 },
        );
      }
      const u = new URL(req.url);
      const path = u.pathname.replace("/client/v4", "");
      if (path === "/zones") {
        const name = u.searchParams.get("name");
        return Response.json({
          success: true,
          result: name === "acme.test" ? [{ id: "z1", name }] : [],
        });
      }
      if (path === "/zones/z1/dns_records" && req.method === "GET") {
        const result = cfRecords.filter(
          (r) => r.type === u.searchParams.get("type") && r.name === u.searchParams.get("name"),
        );
        return Response.json({ success: true, result });
      }
      if (path === "/zones/z1/dns_records" && req.method === "POST") {
        const body = (await req.json()) as CfRecord;
        const rec = { ...body, id: crypto.randomUUID() };
        cfRecords.push(rec);
        syncZone(rec.name);
        return Response.json({ success: true, result: rec });
      }
      const m = /^\/zones\/z1\/dns_records\/(.+)$/.exec(path);
      if (m) {
        const i = cfRecords.findIndex((r) => r.id === m[1]);
        if (i < 0)
          return Response.json(
            { success: false, errors: [{ message: "not found" }] },
            { status: 404 },
          );
        const name = (cfRecords[i] as CfRecord).name;
        if (req.method === "DELETE") cfRecords.splice(i, 1);
        else cfRecords[i] = { ...((await req.json()) as CfRecord), id: m[1] as string };
        syncZone(name);
        return Response.json({ success: true, result: { id: m[1] } });
      }
      return Response.json({ success: false, errors: [{ message: "unknown" }] }, { status: 404 });
    },
  });
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "mail.bunzzle.test",
    BUNZZLE_INBOUND_HOSTNAME: "mail.bunzzle.test",
    BUNZZLE_SOURCE_IPS: "127.0.0.1",
    BUNZZLE_ANOMALY_FLOOR: "20",
    BUNZZLE_CLOUDFLARE_API_TOKEN: "cf-test",
    BUNZZLE_CLOUDFLARE_API_URL: `http://127.0.0.1:${cf.port}/client/v4`,
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  token =
    (await cli("keys", "create", "--name", "app", "--scope", "full", "--rate-limit", "1000")).stdout
      .trim()
      .split("\n")
      .at(-1) ?? "";
}, 30_000);

afterAll(async () => {
  await served.stop();
  cf.stop(true);
  dns.stop();
  mx.stop();
});

describe("reputation on autopilot (M9)", () => {
  test("bunzzle ips: reverse DNS checked, warm-up waiting for the first email", async () => {
    const r = await cli("ips");
    expect(r.stdout).toContain("127.0.0.1  pool main  reverse DNS ok (mail.bunzzle.test)");
    expect(r.stdout).toContain("warm-up starts with the first email");
  });

  test("domains add publishes its records through Cloudflare and verifies on its own", async () => {
    const r = await cli("domains", "add", "acme.test");
    expect(r.stdout).toContain("acme.test: verified");
    expect(cfRecords.map((x) => `${x.type} ${x.name}`).sort()).toEqual(
      [
        "MX bounce.acme.test",
        expect.stringMatching(/^TXT bz\d{6}e\._domainkey\.acme\.test$/),
        expect.stringMatching(/^TXT bz\d{6}r\._domainkey\.acme\.test$/),
        "TXT bounce.acme.test",
      ].sort(),
    );
  });

  test("doctor lists every record, checks DKIM against live DNS, and names what is missing", async () => {
    const r = await cli("doctor");
    expect(r.stdout).toMatch(/\[ok\]\s+DKIM: TXT bz\d{6}r\._domainkey\.acme\.test is correct/);
    expect(r.stdout).toMatch(
      /\[ok\]\s+DKIM self-check: a test message signed now verifies against live DNS/,
    );
    expect(r.stdout).toContain("[ok]   RETURN_PATH_MX: MX bounce.acme.test is correct");
    expect(r.stdout).toMatch(
      /\[warn\] SPF: TXT acme\.test is missing: add "v=spf1 ip4:127\.0\.0\.1 ~all"/,
    );
    expect(r.stdout).toContain("[ok]   127.0.0.1: reverse DNS mail.bunzzle.test");
    expect(r.stdout).toContain("[warn] public URL");
    expect(r.code).toBe(0);
  });

  test("a leaked key: a burst of bulk mail is held and the operator alerted; transactional still flows", async () => {
    const codes: number[] = [];
    for (let i = 0; i < 22; i++) {
      codes.push((await send({ lane: "bulk", to: [`n${i}@example.test`] })).status);
    }
    expect(codes.slice(0, 20).every((c) => c === 200)).toBe(true);
    const held = await send({ lane: "bulk", to: ["x@example.test"] });
    expect(held.status).toBe(403);
    expect(((await held.json()) as { name: string }).name).toBe("sending_paused");
    const alerted = () => served.logs.some((l) => String(l["msg"]).includes("possible leaked key"));
    for (let i = 0; i < 100 && !alerted(); i++) await Bun.sleep(20);
    expect(alerted()).toBe(true);
    expect((await send()).status).toBe(200);
    const holds = await cli("holds");
    expect(holds.stdout).toMatch(/key:\S+ bulk/);
    expect(holds.stdout).toContain("unusual volume");
    const id = /^(\S+)\s+key:/m.exec(holds.stdout)?.[1] as string;
    expect((await cli("holds", "release", id)).code).toBe(0);
    expect((await cli("doctor")).stdout).not.toContain("guards");
  });

  test("DKIM rotation: new keys published, verified, self-checked, switched; old ones kept for the overlap", async () => {
    const before = cfRecords.filter((r) => r.name.includes("_domainkey")).map((r) => r.name);
    const start = await cli("domains", "rotate", "acme.test");
    expect(start.stdout).toContain("acme.test: new keys created");
    expect(start.stdout).toContain("DKIM_NEXT");
    const after = cfRecords.filter((r) => r.name.includes("_domainkey")).map((r) => r.name);
    expect(after.length).toBe(before.length + 2);
    const sw = await cli("domains", "rotate", "acme.test");
    expect(sw.stdout).toContain("acme.test: switched to new keys");
    expect(sw.stdout).toContain("DKIM_RETIRING");
    const doctor = await cli("doctor");
    expect(doctor.stdout).toMatch(
      /DKIM self-check: a test message signed now verifies against live DNS \(bz\d{8}r, bz\d{8}e\)/,
    );
    expect(
      served.logs.some((l) => l["msg"] === "switched to new DKIM keys" && l["selfCheck"] === true),
    ).toBe(true);
  });
});
