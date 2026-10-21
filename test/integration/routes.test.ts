import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns } from "../support/fake-dns.ts";
import { type Served, startServe } from "../support/serve.ts";
import { smtpTalk } from "../support/smtp-client.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
let dns: FakeDns;
let served: Served;
let token: string;
let inbound: number;
let receiver: ReturnType<typeof Bun.serve>;
const secrets = new Map<string, string>();
const posts: { path: string; body: Record<string, unknown>; valid: boolean }[] = [];
let answer: (path: string) => Response = () => new Response("ok");

async function valid(secret: string, req: Request, body: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    Uint8Array.fromBase64(secret.replace(/^whsec_/, "")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const id = req.headers.get("webhook-id") ?? "";
  const ts = req.headers.get("webhook-timestamp") ?? "";
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${id}.${ts}.${body}`)),
  );
  return (req.headers.get("webhook-signature") ?? "").split(" ").includes(`v1,${mac.toBase64()}`);
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

const api = (path: string, init: RequestInit = {}) =>
  fetch(`${served.url}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  });

async function addRoute(address: string, path: string, format?: string) {
  const r = await api("/routes", {
    method: "POST",
    body: JSON.stringify({
      address,
      endpoint: `http://127.0.0.1:${receiver.port}${path}`,
      ...(format ? { format } : {}),
    }),
  });
  expect(r.status).toBe(200);
  const route = (await r.json()) as { id: string; signing_secret: string };
  secrets.set(path, route.signing_secret);
  return route.id;
}

function mail(rcpt: string, lines: string[]) {
  return smtpTalk(inbound, [
    "EHLO sender.example.org",
    "MAIL FROM:<ayse@example.org>",
    `RCPT TO:<${rcpt}>`,
    "DATA",
    `${lines.join("\r\n").replace(/^\./gm, "..")}\r\n.`,
    "QUIT",
  ]);
}

async function until<T>(f: () => T, ok: (v: T) => boolean, ms = 10_000): Promise<T> {
  const end = Date.now() + ms;
  let v = f();
  while (!ok(v) && Date.now() < end) {
    await Bun.sleep(50);
    v = f();
  }
  return v;
}

const postsTo = (path: string) => posts.filter((p) => p.path === path);

beforeAll(async () => {
  dns = await startFakeDns({
    "signed.example": { TXT: ["v=spf1 ip4:127.0.0.1 -all"] },
    "_dmarc.signed.example": { TXT: ["v=DMARC1; p=reject"] },
    "spoof.example": { TXT: ["v=spf1 -all"] },
    "_dmarc.spoof.example": { TXT: ["v=DMARC1; p=reject"] },
  });
  receiver = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      const path = new URL(req.url).pathname;
      const body = await req.text();
      posts.push({
        path,
        body: JSON.parse(body),
        valid: await valid(secrets.get(path) ?? "", req, body),
      });
      return answer(path);
    },
  });
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_INBOUND_HOSTNAME: "in.bunzzle.test",
    BUNZZLE_INBOUND_HOST: "127.0.0.1",
    BUNZZLE_INBOUND_PORT: "0",
    BUNZZLE_INBOUND_REFUSE: "dmarc",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  inbound = served.inboundPort as number;
  const k = await cli("keys", "create", "--name", "t", "--scope", "full");
  token = k.stdout.trim().split("\n").at(-1) ?? "";
  await cli("domains", "add", "acme.test");
}, 30_000);

afterAll(async () => {
  await served.stop();
  receiver.stop(true);
  dns.stop();
});

describe("inbound routes", () => {
  test("SPF, DKIM and DMARC results are in the payload; a DMARC reject is refused", async () => {
    await addRoute("auth@acme.test", "/auth");
    const send = (domain: string) =>
      smtpTalk(inbound, [
        "EHLO mx.sender.test",
        `MAIL FROM:<a@${domain}>`,
        "RCPT TO:<auth@acme.test>",
        "DATA",
        `From: a@${domain}\r\nSubject: hi\r\n\r\nhello\r\n.`,
        "QUIT",
      ]);
    expect((await send("signed.example")).replies[5]).toStartWith("250");
    const [p] = await until(
      () => postsTo("/auth"),
      (l) => l.length > 0,
    );
    expect(p?.body["auth"]).toEqual({
      spf: { result: "pass", domain: "signed.example", scope: "mailfrom", reason: null },
      dkim: [],
      dmarc: { result: "pass", domain: "signed.example", policy: "reject", reason: null },
      blocklists: [],
    });
    expect((await send("spoof.example")).replies[5]).toBe(
      "550 5.7.1 Rejected by the DMARC policy of spoof.example",
    );
    expect(postsTo("/auth")).toHaveLength(1);
  });

  test("routes need a known domain, a valid address and one route per address", async () => {
    const add = (address: string) =>
      api("/routes", {
        method: "POST",
        body: JSON.stringify({ address, endpoint: "https://app.example.org/in" }),
      });
    expect((await add("help@nowhere.test")).status).toBe(422);
    expect((await add("not an address")).status).toBe(422);
    expect((await add("help@acme.test")).status).toBe(200);
    expect((await add("Help@acme.test")).status).toBe(422);
  });

  test("mail for a route is posted as signed JSON; +tag and case still match", async () => {
    await addRoute("support@acme.test", "/support");
    const t = await mail("Support+Billing@acme.test", [
      "From: Ayşe <ayse@example.org>",
      "To: support@acme.test",
      "Subject: =?UTF-8?B?w4dvayBnw7x6ZWw=?=",
      "Message-ID: <q1@example.org>",
      "MIME-Version: 1.0",
      'Content-Type: multipart/mixed; boundary="b"',
      "",
      "--b",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Fatura ekte.",
      ".hidden dot",
      "--b",
      'Content-Type: application/pdf; name="fatura.pdf"',
      "Content-Disposition: attachment",
      "Content-Transfer-Encoding: base64",
      "",
      "JVBERg==",
      "--b--",
    ]);
    expect(t.replies[1]).toContain("SIZE 10485760");
    expect(t.replies[3]).toStartWith("250");
    expect(t.replies[5]).toStartWith("250");
    const [p] = await until(
      () => postsTo("/support"),
      (l) => l.length > 0,
    );
    expect(p?.valid).toBe(true);
    expect(p?.body).toMatchObject({
      mail_from: "ayse@example.org",
      rcpt_to: ["Support+Billing@acme.test"],
      remote_ip: "127.0.0.1",
      tls: false,
      from: "Ayşe <ayse@example.org>",
      subject: "Çok güzel",
      message_id: "<q1@example.org>",
      text: "Fatura ekte.\r\n.hidden dot",
      attachments: [
        {
          filename: "fatura.pdf",
          content_type: "application/pdf",
          content_id: null,
          size: 4,
          content: "JVBERg==",
        },
      ],
    });
  });

  test("a domain wildcard gets the raw message; unrouted addresses are refused at RCPT", async () => {
    const before = await smtpTalk(inbound, [
      "EHLO sender.example.org",
      "MAIL FROM:<ayse@example.org>",
      "RCPT TO:<sales@other.test>",
      "QUIT",
    ]);
    expect(before.replies[3]).toStartWith("550");
    await cli("domains", "add", "other.test");
    await addRoute("*@other.test", "/other", "raw");
    const lines = ["Subject: raw", "", "exactly this"];
    const t = await mail("sales@other.test", lines);
    expect(t.replies[5]).toStartWith("250");
    const [p] = await until(
      () => postsTo("/other"),
      (l) => l.length > 0,
    );
    expect(p?.valid).toBe(true);
    expect(new TextDecoder().decode(Uint8Array.fromBase64(p?.body["raw"] as string))).toBe(
      `${lines.join("\r\n")}\r\n`,
    );
  });

  test("429 and 5xx are retried until the app takes the mail", async () => {
    await addRoute("busy@acme.test", "/busy");
    let calls = 0;
    answer = (path) => {
      if (path !== "/busy") return new Response("ok");
      calls++;
      if (calls === 1)
        return new Response("slow down", { status: 429, headers: { "retry-after": "1" } });
      if (calls === 2) return new Response("oops", { status: 503 });
      return new Response("ok");
    };
    await mail("busy@acme.test", ["Subject: busy", "", "x"]);
    const l = await until(
      () => postsTo("/busy"),
      (x) => x.length >= 3,
    );
    expect(l).toHaveLength(3);
    expect(new Set(l.map((p) => p.body["id"])).size).toBe(1);
    await Bun.sleep(300);
    expect(postsTo("/busy")).toHaveLength(3);
  });

  test("a 4xx answer fails at once; `routes retry` sends it again", async () => {
    const id = await addRoute("strict@acme.test", "/strict");
    let refuse = true;
    answer = (path) => new Response("", { status: path === "/strict" && refuse ? 400 : 200 });
    await mail("strict@acme.test", ["Subject: strict", "", "x"]);
    await until(
      () => postsTo("/strict"),
      (x) => x.length > 0,
    );
    await Bun.sleep(300);
    expect(postsTo("/strict")).toHaveLength(1);
    refuse = false;
    const r = await cli("routes", "retry", id);
    expect(r.stdout).toContain("1 failed message queued again.");
    const l = await until(
      () => postsTo("/strict"),
      (x) => x.length > 1,
    );
    expect(l).toHaveLength(2);
    expect(l[1]?.body["id"]).toBe(l[0]?.body["id"]);
  });

  test("routes can be listed and removed; a removed address is refused again", async () => {
    const list = await cli("routes", "list");
    expect(list.stdout).toContain("support@acme.test");
    expect(list.stdout).toContain("*@other.test  ");
    const routes = (await (await api("/routes")).json()) as {
      data: { id: string; address: string }[];
    };
    const busy = routes.data.find((r) => r.address === "busy@acme.test");
    expect((await api(`/routes/${busy?.id}`, { method: "DELETE" })).status).toBe(200);
    expect((await api(`/routes/${busy?.id}`, { method: "DELETE" })).status).toBe(404);
    const t = await smtpTalk(inbound, [
      "EHLO sender.example.org",
      "MAIL FROM:<ayse@example.org>",
      "RCPT TO:<busy@acme.test>",
      "QUIT",
    ]);
    expect(t.replies[3]).toStartWith("550");
  });
});
