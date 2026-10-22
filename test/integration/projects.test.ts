import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { OPERATIONS } from "../../src/http/openapi.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
let served: Served;
let a: string;
let b: string;
let admin: string;
const owned: Record<string, string> = {};

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  return (await new Response(proc.stdout).text()).trim();
}

const lastLine = (s: string) => s.split("\n").at(-1) ?? "";

async function call(key: string, method: string, path: string, body?: unknown) {
  const r = await fetch(`${served.url}${path}`, {
    method,
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: r.status, text: await r.text() };
}

const json = (text: string) => JSON.parse(text) as Record<string, unknown>;

beforeAll(async () => {
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_SOURCE_IPS: "127.0.0.1",
  });
  a = lastLine(
    await cli(
      "keys",
      "create",
      "--name",
      "a",
      "--scope",
      "full",
      "--test",
      "--rate-limit",
      "10000",
    ),
  );
  admin = lastLine(
    await cli("keys", "create", "--name", "ops", "--admin", "--rate-limit", "10000"),
  );
  await call(admin, "POST", "/projects", { name: "other" });
  b = json(
    (
      await call(admin, "POST", "/projects/other/keys", {
        name: "b",
        scope: "full",
        rate_limit: 10000,
      })
    ).text,
  )["token"] as string;

  await call(a, "POST", "/domains", { name: "acme.test" });
  const email = await call(a, "POST", "/emails", {
    from: "x@acme.test",
    to: "r@dest.test",
    subject: "s",
    text: "t",
    scheduled_at: new Date(Date.now() + 3_600_000).toISOString(),
  });
  owned["emails"] = json(email.text)["id"] as string;
  owned["webhooks"] = json(
    (await call(a, "POST", "/webhooks", { endpoint: "https://hooks.acme.test/x" })).text,
  )["id"] as string;
  owned["routes"] = json(
    (
      await call(a, "POST", "/routes", {
        address: "in@acme.test",
        endpoint: "https://hooks.acme.test/in",
      })
    ).text,
  )["id"] as string;
  owned["templates"] = json(
    (await call(a, "POST", "/templates", { name: "welcome", subject: "Hi", text: "Hi" })).text,
  )["id"] as string;
  await call(a, "POST", "/suppressions", { email: "blocked@dest.test" });
  owned["pool-rules"] = json(
    (await call(a, "POST", "/pool-rules", { match: "dest.test", pool: "main" })).text,
  )["id"] as string;
  owned["domains"] = "acme.test";
  owned["suppressions"] = "blocked@dest.test";
}, 30_000);

afterAll(async () => {
  await served.stop();
});

const BODIES: Record<string, unknown> = {
  "PATCH /emails/:id": { scheduled_at: new Date(Date.now() + 7_200_000).toISOString() },
  "PATCH /domains/:name": { ip_pool: null },
  "PATCH /templates/:id": { subject: "x" },
  "POST /templates/:id/preview": {},
  "POST /projects/:id/keys": { name: "x" },
  "POST /projects": { name: "y" },
  "POST /webhooks/:id/resend": { from: new Date(0).toISOString(), to: new Date().toISOString() },
  "PATCH /projects/:id": { suspended: true },
  "POST /queue/suspensions": { target: "domain:dest.test", reason: "r" },
  "POST /queue/cancel": { reason: "r", domain: "dest.test", dry_run: true },
  "POST /queue/fail": { reason: "r", domain: "dest.test", dry_run: true },
};

const CREATES = new Set([
  "POST /emails",
  "POST /emails/batch",
  "POST /domains",
  "POST /webhooks",
  "POST /routes",
  "POST /templates",
  "POST /suppressions",
  "POST /pool-rules",
]);

describe("projects", () => {
  test("another project's key never finds, lists or changes this project's objects", async () => {
    expect(Object.values(owned).every(Boolean)).toBe(true);
    const secrets = Object.values(owned);
    const problems: string[] = [];
    for (const op of OPERATIONS) {
      const name = `${op.method} ${op.path}`;
      if (op.scope === null || CREATES.has(name)) continue;
      const body = BODIES[name] ?? (op.method === "GET" || op.method === "DELETE" ? undefined : {});
      const params = [...op.path.matchAll(/:(\w+)/g)].map((m) => m[1]);
      let path = op.path;
      let want: number[];
      if (op.scope.includes("admin")) {
        path = path.replace(/:\w+/g, "other");
        want = [403];
      } else if (op.path.startsWith("/queue/suspensions") || name === "POST /queue/suspensions") {
        path = path.replace(":target", "domain:dest.test");
        want = [403];
      } else if (op.path.startsWith("/holds/")) {
        path = path.replace(":id", "0198f6a2-0000-7000-8000-000000000000");
        want = [404];
      } else if (params.length > 0) {
        const kind = op.path.split("/")[1] as string;
        const value = owned[kind];
        if (!value) {
          problems.push(`${name}: no cross-project case`);
          continue;
        }
        path = path.replace(/:\w+/, encodeURIComponent(value));
        want = [404];
      } else {
        want = [200];
      }
      const r = await call(b, op.method, path, body);
      if (!want.includes(r.status)) problems.push(`${name}: ${r.status} ${r.text.slice(0, 120)}`);
      if (r.status === 200) {
        for (const s of secrets) {
          if (r.text.includes(s)) problems.push(`${name}: shows ${s}`);
        }
        if (name === "POST /queue/cancel" || name === "POST /queue/fail") {
          if (json(r.text)["emails"] !== 0)
            problems.push(`${name}: counts another project's email`);
        }
      }
    }
    expect(problems).toEqual([]);
    const own = await call(a, "GET", `/emails/${owned["emails"]}`);
    expect(own.status).toBe(200);
  }, 60_000);
});
