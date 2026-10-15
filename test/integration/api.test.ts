import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { verifyDkim } from "../support/dkim-verify.ts";
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
let full: string;

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

async function newKey(...flags: string[]): Promise<string> {
  const r = await cli("keys", "create", "--name", "t", ...flags);
  if (r.code !== 0) throw new Error(`keys create failed: ${r.stderr}`);
  return (r.stdout.trim().split("\n").at(-1) ?? "").trim();
}

function api(path: string, init: RequestInit & { token?: string | null } = {}) {
  const { token = full, ...rest } = init;
  return fetch(`${served.url}${path}`, {
    ...rest,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(rest.headers as Record<string, string> | undefined),
    },
  });
}

const email = (extra: Record<string, unknown> = {}) => ({
  from: "Acme <hello@acme.test>",
  to: ["user@example.test"],
  subject: "Your sign-in link",
  html: "<p>Click <a href='https://acme.test/x'>here</a></p>",
  text: "Click https://acme.test/x",
  ...extra,
});

const send = (body: unknown, init: RequestInit & { token?: string | null } = {}) =>
  api("/emails", { method: "POST", body: JSON.stringify(body), ...init });

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
  full = await newKey("--scope", "full");
});

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

describe("API keys", () => {
  test("missing, malformed and unknown keys are refused", async () => {
    const none = await send(email(), { token: null });
    expect(none.status).toBe(401);
    expect(((await none.json()) as { name: string }).name).toBe("missing_api_key");
    expect((await send(email(), { token: "nope" })).status).toBe(403);
    const unknown = `bz_${"A".repeat(43)}`;
    expect(
      ((await (await send(email(), { token: unknown })).json()) as { name: string }).name,
    ).toBe("invalid_api_key");
  });

  test("only a hash is stored: the token appears nowhere in the database", async () => {
    const db = await Bun.file(`${served.dir}/data/bunzzle.db`).bytes();
    const wal = Bun.file(`${served.dir}/data/bunzzle.db-wal`);
    const all =
      new TextDecoder("latin1").decode(db) +
      ((await wal.exists()) ? new TextDecoder("latin1").decode(await wal.bytes()) : "");
    expect(all.includes(full)).toBe(false);
    expect(all.includes(full.slice(0, 10))).toBe(true);
  });
});

describe("sending domains (only verified domains can send)", () => {
  test("an unregistered domain is refused", async () => {
    const r = await send(email());
    expect(r.status).toBe(403);
    expect(((await r.json()) as { message: string }).message).toContain("not registered");
  });

  test("domains add creates DKIM keys and prints the records; sending waits for DNS", async () => {
    const added = await cli("domains", "add", "acme.test");
    expect(added.code).toBe(0);
    expect(added.stdout).toContain("acme.test: pending");
    expect(added.stdout).toMatch(/bz\d{6}r\._domainkey\.acme\.test/);
    expect(added.stdout).toContain("v=spf1 a mx ~all");
    const r = await send(email());
    expect(r.status).toBe(403);
    expect(((await r.json()) as { message: string }).message).toContain("not verified yet");
  });

  test("after publishing the DKIM records the domain verifies", async () => {
    const d = (await (await api("/domains/acme.test")).json()) as {
      records: { record: string; name: string; value: string }[];
    };
    for (const r of d.records.filter((x) => x.record === "DKIM")) zone[r.name] = { TXT: [r.value] };
    const v = await cli("domains", "verify", "acme.test");
    expect(v.stdout).toContain("acme.test: verified");
    expect(v.stdout).toContain("[MISSING] SPF (recommended)");
    const list = (await (await api("/domains")).json()) as {
      data: { name: string; status: string }[];
    };
    expect(list.data).toEqual([expect.objectContaining({ name: "acme.test", status: "verified" })]);
  });
});

describe("POST /emails and GET /emails/:id", () => {
  test("curl-style send: delivered, DKIM-signed, with MX and TLS in the timeline", async () => {
    const r = await send(
      email({ cc: "boss@example.test", tags: [{ name: "kind", value: "login" }] }),
    );
    expect(r.status).toBe(200);
    const { id } = (await r.json()) as { id: string };
    let view: Record<string, unknown> = {};
    for (let i = 0; i < 100; i++) {
      view = (await (await api(`/emails/${id}`)).json()) as Record<string, unknown>;
      if (view["last_event"] === "delivered") break;
      await Bun.sleep(100);
    }
    expect(view).toMatchObject({
      object: "email",
      id,
      from: "Acme <hello@acme.test>",
      to: ["user@example.test"],
      cc: ["boss@example.test"],
      last_event: "delivered",
      tags: [{ name: "kind", value: "login" }],
      html: null,
    });
    const recipients = view["recipients"] as { email: string; status: string }[];
    expect(recipients.map((x) => [x.email, x.status])).toEqual([
      ["boss@example.test", "delivered"],
      ["user@example.test", "delivered"],
    ]);
    const attempt = (view["attempts"] as Record<string, unknown>[])[0] as {
      mx: string[];
      tls_policy: string;
      sessions: { host: string; tls: { status: string; version: string; rule: string } }[];
      results: { email: string; reply: string }[];
    };
    expect(attempt.mx).toEqual(["mx.example.test"]);
    expect(attempt.tls_policy).toBe("opportunistic");
    expect(attempt.sessions[0]?.tls).toMatchObject({ status: "unverified", rule: "opportunistic" });
    expect(attempt.sessions[0]?.tls.version).toMatch(/^TLSv1\.[23]$/);
    expect(attempt.results).toHaveLength(2);

    const received =
      mx.sessions.flatMap((s) => s.messages).find((m) => m.includes("sign-in link")) ?? "";
    const d = (await (await api("/domains/acme.test")).json()) as {
      records: { record: string; name: string; value: string }[];
    };
    const keys = Object.fromEntries(
      d.records
        .filter((x) => x.record === "DKIM")
        .map((x) => [
          x.name.split(".")[0],
          {
            algorithm: x.value.includes("k=rsa")
              ? ("rsa-sha256" as const)
              : ("ed25519-sha256" as const),
            key: Uint8Array.fromBase64(/p=([^;\s]+)/.exec(x.value)?.[1] ?? ""),
          },
        ]),
    );
    expect((await verifyDkim(received, keys)).every((v) => v.ok)).toBe(true);
    expect(received).not.toMatch(/^bcc:/im);
  }, 15_000);

  test("Idempotency-Key: same request gives the same id, a different body is a conflict", async () => {
    const headers = { "idempotency-key": "order-42" };
    const a = (await (await send(email(), { headers })).json()) as { id: string };
    const b = (await (await send(email(), { headers })).json()) as { id: string };
    expect(b.id).toBe(a.id);
    const c = await send(email({ subject: "changed" }), { headers });
    expect(c.status).toBe(409);
    expect(((await c.json()) as { name: string }).name).toBe("invalid_idempotent_request");
  });

  test("validation errors are 422 with a clear message", async () => {
    const noBody = await send({ from: "hello@acme.test", to: "u@example.test", subject: "x" });
    expect(noBody.status).toBe(422);
    expect(((await noBody.json()) as { message: string }).message).toContain("html");
    const badFrom = await send(email({ from: "not an address" }));
    expect(((await badFrom.json()) as { message: string }).message).toContain(
      "Invalid `from` field",
    );
    const byUrl = await send(
      email({ attachments: [{ filename: "a.pdf", path: "http://169.254.169.254/latest" }] }),
    );
    expect(byUrl.status).toBe(422);
    const tooFar = await send(
      email({ scheduled_at: new Date(Date.now() + 100 * 3_600_000).toISOString() }),
    );
    expect(tooFar.status).toBe(422);
    const notJson = await api("/emails", { method: "POST", body: "{" });
    expect(notJson.status).toBe(422);
  });

  test("unknown email id is 404", async () => {
    expect((await api("/emails/0190aaaa-0000-7000-8000-000000000000")).status).toBe(404);
  });
});

describe("scopes, domain limits, rate limits, revocation", () => {
  test("a send-only key cannot read, a read-only key cannot send", async () => {
    const sendOnly = await newKey("--scope", "send");
    expect((await send(email(), { token: sendOnly })).status).toBe(200);
    expect((await api("/domains", { token: sendOnly })).status).toBe(403);
    const readOnly = await newKey("--scope", "read");
    const r = await send(email(), { token: readOnly });
    expect(r.status).toBe(403);
    expect(((await r.json()) as { name: string }).name).toBe("restricted_api_key");
    expect((await api("/domains", { token: readOnly })).status).toBe(200);
  });

  test("a key limited to one domain cannot send from another", async () => {
    const limited = await newKey("--scope", "send", "--domain", "other.test");
    const r = await send(email(), { token: limited });
    expect(r.status).toBe(403);
    expect(((await r.json()) as { message: string }).message).toContain(
      "cannot send from acme.test",
    );
  });

  test("per-key rate limit answers 429 with Retry-After", async () => {
    const slow = await newKey("--scope", "read", "--rate-limit", "2");
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await api("/domains", { token: slow })).status);
    expect(codes.slice(0, 2)).toEqual([200, 200]);
    const limited = await api("/domains", { token: slow });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("1");
  });

  test("a revoked key stops working at once", async () => {
    const r = await cli("keys", "create", "--name", "temp", "--scope", "read");
    const token = r.stdout.trim().split("\n").at(-1) ?? "";
    expect((await api("/domains", { token })).status).toBe(200);
    const list = await cli("keys", "list");
    const id =
      list.stdout
        .split("\n")
        .find((l) => l.includes(" temp "))
        ?.split(" ")[0] ?? "";
    expect((await cli("keys", "revoke", id)).code).toBe(0);
    expect((await api("/domains", { token })).status).toBe(403);
  });
});
