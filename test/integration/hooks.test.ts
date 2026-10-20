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
let checker: ReturnType<typeof Bun.serve>;
let scanner: ReturnType<typeof Bun.serve>;
let checkReply: () => Response | Promise<Response> = () => Response.json({ action: "accept" });
let score = 0;
const checked: { email: Record<string, unknown>; api_key_id: string | null }[] = [];
const scanned: { body: string; type: string | null; from: string | null }[] = [];

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
  return { stdout: stdout.trim(), stderr, code };
}

const send = (extra: Record<string, unknown> = {}) =>
  fetch(`${served.url}/emails`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({
      from: "hello@acme.test",
      to: "user@example.test",
      subject: `Hooked ${crypto.randomUUID()}`,
      text: "Hello",
      ...extra,
    }),
  });

async function received(subject: string): Promise<string> {
  for (let i = 0; i < 100; i++) {
    const m = mx.sessions.flatMap((s) => s.messages).find((x) => x.includes(subject));
    if (m) return m;
    await Bun.sleep(100);
  }
  return "";
}

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  checker = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      checked.push((await req.json()) as (typeof checked)[number]);
      return checkReply();
    },
  });
  scanner = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      scanned.push({
        body: await req.text(),
        type: req.headers.get("content-type"),
        from: req.headers.get("from"),
      });
      return Response.json({ score, action: "no action" });
    },
  });
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  token = (
    await cli("keys", "create", "--name", "t", "--scope", "send", "--rate-limit", "1000")
  ).stdout
    .split("\n")
    .at(-1) as string;
  await cli("domains", "add", "acme.test");
  const show = await cli("domains", "show", "acme.test");
  for (const m of show.stdout.matchAll(
    /TXT {2}(\S+\._domainkey\.acme\.test)\n\s+(v=DKIM1[^\n]+)/g,
  )) {
    zone[m[1] as string] = { TXT: [m[2] as string] };
  }
  expect((await cli("domains", "verify", "acme.test")).stdout).toContain("acme.test: verified");
}, 30_000);

afterAll(async () => {
  await served.stop();
  checker.stop(true);
  scanner.stop(true);
  dns.stop();
  mx.stop();
});

describe("hooks before sending", () => {
  test("without hooks nothing is called", async () => {
    expect((await send()).status).toBe(200);
    expect(checked).toHaveLength(0);
    expect(scanned).toHaveLength(0);
    expect((await cli("hooks", "list")).stdout).toContain("No hooks");
  });

  test("a check hook sees the email and can change it", async () => {
    const add = await cli("hooks", "add", "check", `http://127.0.0.1:${checker.port}/check`);
    expect(add.code).toBe(0);
    checkReply = () =>
      Response.json({
        action: "change",
        email: { subject: "Changed by the hook", tags: [{ name: "checked", value: "yes" }] },
      });
    const r = await send({
      attachments: [{ filename: "a.txt", content: btoa("hi"), content_type: "text/plain" }],
    });
    expect(r.status).toBe(200);
    const seen = checked.at(-1);
    expect(seen?.email).toMatchObject({
      from: "hello@acme.test",
      text: "Hello",
      attachments: [{ filename: "a.txt", content_type: "text/plain" }],
    });
    expect(JSON.stringify(seen)).not.toContain(btoa("hi"));
    expect(seen?.api_key_id).toMatch(/\S+/);
    const raw = await received("Changed by the hook");
    expect(raw).toContain("Subject: Changed by the hook");
    expect(raw).toContain("a.txt");
  });

  test("a check hook can refuse, and cannot change the recipients", async () => {
    checkReply = () => Response.json({ action: "refuse", reason: "blocked word" });
    const r = await send();
    expect(r.status).toBe(422);
    expect(await r.json()).toMatchObject({
      name: "refused",
      message: "Refused before sending: blocked word",
    });
    checkReply = () => Response.json({ action: "change", email: { to: "other@example.test" } });
    expect((await send()).status).toBe(200);
  });

  test("a hook that fails is skipped, or refuses with 503 when set to", async () => {
    checkReply = () => new Response("down", { status: 500 });
    expect((await send()).status).toBe(200);
    await cli("hooks", "remove", (await cli("hooks", "list")).stdout.split(/\s+/)[0] as string);
    await cli(
      "hooks",
      "add",
      "check",
      `http://127.0.0.1:${checker.port}/check`,
      "--on-error",
      "refuse",
      "--timeout-ms",
      "300",
    );
    checkReply = async () => {
      await Bun.sleep(1_000);
      return Response.json({ action: "accept" });
    };
    const r = await send();
    expect(r.status).toBe(503);
    expect(r.headers.get("retry-after")).toBe("5");
    expect(((await r.json()) as { name: string }).name).toBe("hook_unavailable");
    const all = (await cli("hooks", "list")).stdout;
    for (const line of all.split("\n"))
      await cli("hooks", "remove", line.split(/\s+/)[0] as string);
    expect((await cli("hooks", "list")).stdout).toContain("No hooks");
  });

  test("a scan hook gets the whole message and refuses at the score limit", async () => {
    const add = await cli(
      "hooks",
      "add",
      "scan",
      `http://127.0.0.1:${scanner.port}/scan`,
      "--max-score",
      "6",
    );
    expect(add.stdout).toContain("refuse at score 6");
    expect((await cli("hooks", "add", "scan", "http://127.0.0.1:1/")).code).not.toBe(0);
    score = 2.5;
    expect((await send({ subject: "Clean one" })).status).toBe(200);
    expect(scanned.at(-1)?.type).toBe("message/rfc822");
    expect(scanned.at(-1)?.from).toBe("hello@acme.test");
    expect(scanned.at(-1)?.body).toContain("Subject: Clean one");
    score = 9;
    const r = await send();
    expect(r.status).toBe(422);
    expect(((await r.json()) as { message: string }).message).toBe(
      "The content check refused this email (score 9, limit 6).",
    );
  });
});
