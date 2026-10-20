import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { type Served, startServe } from "../support/serve.ts";
import { issue, privateKeyPem } from "../support/x509.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let token: string;
let certs: string;
let receiver: ReturnType<typeof Bun.serve>;
const hooks: { type: string; data: Record<string, unknown> }[] = [];

function api(path: string, init: RequestInit = {}) {
  return fetch(`${served.url}${path}`, {
    ...init,
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
  });
}

const patch = (body: unknown) =>
  api("/domains/acme.test", { method: "PATCH", body: JSON.stringify(body) });

const send = (extra: Record<string, unknown> = {}) =>
  api("/emails", {
    method: "POST",
    body: JSON.stringify({
      from: "hello@acme.test",
      to: "user@example.test",
      subject: `Tracked ${crypto.randomUUID()}`,
      html: `<html><body><a href="https://acme.test/orders?id=1&amp;x=2">Order</a> <a data-no-track href="https://acme.test/reset">Reset</a></body></html>`,
      text: "Order: https://acme.test/orders?id=1&x=2",
      ...extra,
    }),
  });

async function until<T>(fn: () => Promise<T> | T, ok: (v: T) => boolean): Promise<T> {
  let v = await fn();
  for (let i = 0; i < 100 && !ok(v); i++) {
    await Bun.sleep(100);
    v = await fn();
  }
  return v;
}

async function received(subject: string): Promise<string> {
  const raw = await until(
    () => mx.sessions.flatMap((s) => s.messages).find((m) => m.includes(subject)) ?? "",
    (m) => m !== "",
  );
  return raw.replace(/=\r\n/g, "").replace(/=3D/g, "=");
}

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

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  receiver = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      hooks.push((await req.json()) as { type: string; data: Record<string, unknown> });
      return new Response("ok");
    },
  });
  certs = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-certs-${crypto.randomUUID()}`;
  const cert = await issue({ name: "links.acme.test", dns: ["links.acme.test"] });
  await Bun.write(`${certs}/track/links.acme.test/cert.pem`, cert.pem);
  await Bun.write(`${certs}/track/links.acme.test/key.pem`, await privateKeyPem(cert));
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_PUBLIC_URL: "https://mail.bunzzle.test",
    BUNZZLE_CERTS_DIR: certs,
    BUNZZLE_TRACK_HOST: "127.0.0.1",
    BUNZZLE_TRACK_PORT: "0",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  const k = await cli("keys", "create", "--name", "t", "--scope", "full");
  token = k.stdout.trim().split("\n").at(-1) ?? "";
  await cli("domains", "add", "acme.test");
  const d = (await (await api("/domains/acme.test")).json()) as {
    records: { record: string; name: string; value: string }[];
  };
  for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
  expect((await cli("domains", "verify", "acme.test")).stdout).toContain("acme.test: verified");
  await api("/webhooks", {
    method: "POST",
    body: JSON.stringify({
      endpoint: `http://127.0.0.1:${receiver.port}/hooks`,
      events: ["email.opened", "email.clicked"],
    }),
  });
}, 30_000);

afterAll(async () => {
  await served.stop();
  receiver.stop(true);
  dns.stop();
  mx.stop();
  await Bun.$`rm -rf ${certs}`.quiet();
});

describe("open and click tracking", () => {
  test("off by default: links and body stay as they are", async () => {
    const r = await send({ subject: "Untracked one" });
    expect(r.status).toBe(200);
    const raw = await received("Untracked one");
    expect(raw).toContain('href="https://acme.test/orders?id=1&amp;x=2"');
    expect(raw).not.toContain("/o/");
  });

  test("the tracking host must be a subdomain and verified before an email can ask for it", async () => {
    expect((await patch({ tracking: { host: "links.other.test" } })).status).toBe(422);
    const set = (await (
      await patch({ tracking: { host: "links.acme.test", opens: true, clicks: true } })
    ).json()) as { tracking: Record<string, unknown> };
    expect(set.tracking).toMatchObject({
      host: "links.acme.test",
      opens: true,
      clicks: true,
      record: {
        type: "CNAME",
        name: "links.acme.test",
        value: "mail.bunzzle.test",
        status: "missing",
      },
    });
    const asked = await send({ tracking: { clicks: true } });
    expect(asked.status).toBe(422);
    expect(((await asked.json()) as { message: string }).message).toContain("not verified");
    expect((await send({ subject: "Pending host" })).status).toBe(200);
    expect(await received("Pending host")).not.toContain("links.acme.test");
  });

  test("once the CNAME is in place, links are signed and the open pixel is added", async () => {
    zone["links.acme.test"] = { CNAME: "mail.bunzzle.test" };
    const set = (await (await patch({ tracking: { host: "links.acme.test" } })).json()) as {
      tracking: { record: { status: string } };
    };
    expect(set.tracking.record.status).toBe("verified");
    const got = (await (await api("/domains/acme.test")).json()) as Record<string, unknown>;
    expect(got["tracking"]).toMatchObject({ host: "links.acme.test", opens: true, clicks: true });

    const r = await send({ subject: "Tracked one" });
    const { id } = (await r.json()) as { id: string };
    const raw = await received("Tracked one");
    const click = /href="(https:\/\/links\.acme\.test\/c\/[a-z2-7]+\/[A-Za-z0-9_-]+)"/.exec(
      raw,
    )?.[1];
    const open = /src="(https:\/\/links\.acme\.test\/o\/[a-z2-7]+)"/.exec(raw)?.[1];
    expect(click).toBeDefined();
    expect(open).toBeDefined();
    expect(raw).toContain('href="https://acme.test/reset"');
    expect(raw).toContain("Order: https://acme.test/orders?id=1&x=2");

    const local = (u: string) => u.replace("https://links.acme.test", served.url);
    const head = await fetch(local(click as string), { method: "HEAD", redirect: "manual" });
    expect(head.status).toBe(302);
    const go = await fetch(local(click as string), {
      redirect: "manual",
      headers: { "user-agent": "test-agent" },
    });
    expect(go.status).toBe(302);
    expect(go.headers.get("location")).toBe("https://acme.test/orders?id=1&x=2");
    expect(go.headers.get("cache-control")).toContain("no-store");

    const tls = await fetch(
      (open as string).replace("https://links.acme.test", `https://127.0.0.1:${served.trackPort}`),
      { tls: { rejectUnauthorized: false } },
    );
    expect(tls.status).toBe(200);
    expect(tls.headers.get("content-type")).toBe("image/gif");

    const view = await until(
      async () => (await (await api(`/emails/${id}`)).json()) as { events: { type: string }[] },
      (v) => v.events.some((e) => e.type === "opened"),
    );
    const types = view.events.map((e) => e.type);
    expect(types.filter((t) => t === "clicked")).toHaveLength(1);
    expect(types.filter((t) => t === "opened")).toHaveLength(1);
    expect(view.events.find((e) => e.type === "clicked")).toMatchObject({
      link: "https://acme.test/orders?id=1&x=2",
      user_agent: "test-agent",
    });

    const hook = await until(
      () => hooks.find((h) => h.type === "email.clicked"),
      (h) => h !== undefined,
    );
    expect(hook?.data).toMatchObject({
      email_id: id,
      click: { link: "https://acme.test/orders?id=1&x=2" },
      user_agent: "test-agent",
    });
    expect(
      (
        await until(
          () => hooks.find((h) => h.type === "email.opened"),
          (h) => h !== undefined,
        )
      )?.data["email_id"],
    ).toBe(id);
  });

  test("links without a valid signature are refused", async () => {
    const raw = await received("Tracked one");
    const click = /href="https:\/\/links\.acme\.test(\/c\/[a-z2-7]+)\/([A-Za-z0-9_-]+)"/.exec(raw);
    const path = click?.[1] as string;
    const other = new TextEncoder()
      .encode("https://evil.example/")
      .toBase64({ alphabet: "base64url", omitPadding: true });
    expect((await fetch(`${served.url}${path}/${other}`, { redirect: "manual" })).status).toBe(404);
    const flipped = `${path.slice(0, 13)}${path[13] === "a" ? "b" : "a"}${path.slice(14)}`;
    expect(
      (await fetch(`${served.url}${flipped}/${click?.[2]}`, { redirect: "manual" })).status,
    ).toBe(404);
    expect((await fetch(`${served.url}/c/abc/def`, { redirect: "manual" })).status).toBe(404);
  });

  test("an email can turn tracking off; without html it cannot ask for it", async () => {
    await send({ subject: "Opted out", tracking: { opens: false, clicks: false } });
    expect(await received("Opted out")).not.toContain("links.acme.test");
    const r = await api("/emails", {
      method: "POST",
      body: JSON.stringify({
        from: "hello@acme.test",
        to: "user@example.test",
        subject: "x",
        text: "x",
        tracking: { opens: true },
      }),
    });
    expect(r.status).toBe(422);
  });

  test("the CLI sets and removes the tracking host", async () => {
    const on = await cli("domains", "tracking", "acme.test", "links.acme.test", "--clicks");
    expect(on.stdout).toContain("acme.test tracks clicks through links.acme.test.");
    expect(on.stdout).toContain("[ok] CNAME  links.acme.test  mail.bunzzle.test");
    const off = await cli("domains", "tracking", "acme.test", "none");
    expect(off.stdout).toContain("acme.test has no tracking.");
    expect(
      ((await (await api("/domains/acme.test")).json()) as Record<string, unknown>)["tracking"],
    ).toBeNull();
  });
});
