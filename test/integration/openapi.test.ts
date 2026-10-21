import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { OPERATIONS, openApi } from "../../src/http/openapi.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";
import { checkJson } from "../support/json-schema.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const zone: Zone = {
  "example.test": { MX: [[10, "mx.example.test"]] },
  "mx.example.test": { A: ["127.0.0.1"] },
};
const doc = openApi();
let dns: FakeDns;
let mx: FakeMx;
let served: Served;
let token: string;
let adminToken: string;
const problems: string[] = [];
const seen = new Set<string>();

function operationFor(method: string, path: string) {
  const bare = path.split("?")[0] as string;
  return OPERATIONS.find((o) => {
    if (o.method !== method) return false;
    const re = new RegExp(`^${o.path.replace(/:\w+/g, "[^/]+")}$`);
    return re.test(bare);
  });
}

async function call(method: string, path: string, body?: unknown, as = token) {
  const r = await fetch(`${served.url}${path}`, {
    method,
    headers: { authorization: `Bearer ${as}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const json = (await r.json()) as Record<string, unknown>;
  const op = operationFor(method, path);
  if (!op) {
    problems.push(`${method} ${path}: not described`);
    return json;
  }
  const name = r.status < 300 ? op.response?.[0] : "Error";
  if (name) {
    seen.add(`${op.method} ${op.path} ${r.status < 300 ? "ok" : "error"}`);
    for (const p of checkJson({ $ref: `#/components/schemas/${name}` }, json, doc)) {
      problems.push(`${method} ${path} (${r.status}): ${p}`);
    }
  }
  return json;
}

async function cli(...args: string[]) {
  const proc = Bun.spawn(["bun", MAIN, ...args], {
    cwd: served.dir,
    env: { PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" },
    stdout: "pipe",
    stderr: "pipe",
  });
  return (await new Response(proc.stdout).text()).trim();
}

beforeAll(async () => {
  dns = await startFakeDns(zone);
  mx = startFakeMx();
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
    BUNZZLE_EHLO_NAME: "out.bunzzle.test",
    BUNZZLE_PUBLIC_URL: "https://mail.bunzzle.test",
    BUNZZLE_INBOUND_HOSTNAME: "in.bunzzle.test",
    BUNZZLE_INBOUND_HOST: "127.0.0.1",
    BUNZZLE_INBOUND_PORT: "0",
    BUNZZLE_RETRY_SCALE: "0.001",
  });
  const keys = await cli(
    "keys",
    "create",
    "--name",
    "t",
    "--scope",
    "full",
    "--rate-limit",
    "10000",
  );
  token = keys.split("\n").at(-1) ?? "";
  adminToken = (await cli("keys", "create", "--name", "ops", "--admin")).split("\n").at(-1) ?? "";
}, 30_000);

afterAll(async () => {
  await served.stop();
  dns.stop();
  mx.stop();
});

describe("API responses match openapi.json", () => {
  test("every operation, success and error", async () => {
    await call("POST", "/emails", {});
    await call("POST", "/domains", { name: "acme.test" });
    const d = await call("GET", "/domains/acme.test");
    const records = d["records"] as { record: string; name: string; value: string }[];
    for (const r of records.filter((x) => x.record === "DKIM")) {
      zone[r.name] = { TXT: [r.value] };
    }
    await call("POST", "/domains/acme.test/verify");
    await call("GET", "/domains");
    await call("PATCH", "/domains/acme.test", { tracking: { host: "links.acme.test" } });
    await call("GET", "/domains/acme.test");
    await call("GET", "/domains/acme.test/dmarc");
    const sent = await call("POST", "/emails", {
      from: "a@acme.test",
      to: "u@example.test",
      subject: "s",
      html: "<a href='https://x.test/'>x</a>",
      tags: [{ name: "k", value: "v" }],
    });
    await call("POST", "/emails/batch", [
      { from: "a@acme.test", to: "u@example.test", subject: "s", text: "t" },
    ]);
    const later = new Date(Date.now() + 3_600_000).toISOString();
    const s = await call("POST", "/emails", {
      from: "a@acme.test",
      to: "u@example.test",
      subject: "s",
      text: "t",
      scheduled_at: later,
    });
    await call("PATCH", `/emails/${s["id"]}`, { scheduled_at: later });
    await call("POST", `/emails/${s["id"]}/cancel`);
    for (let i = 0; i < 50; i++) {
      const e = await call("GET", `/emails/${sent["id"]}`);
      if (e["last_event"] === "delivered") break;
      await Bun.sleep(100);
    }
    await call("GET", "/emails/does-not-exist");
    await call("GET", "/emails?limit=5");
    await call("GET", "/stats");
    const w = await call("POST", "/webhooks", { endpoint: "https://hooks.example.com/x" });
    await call("GET", "/webhooks");
    await call("DELETE", `/webhooks/${w["id"]}`);
    const route = await call("POST", "/routes", {
      address: "*@acme.test",
      endpoint: "https://app.example.com/in",
    });
    await call("GET", "/routes");
    await call("POST", `/routes/${route["id"]}/retry`);
    await call("DELETE", `/routes/${route["id"]}`);
    const t = await call("POST", "/templates", {
      name: "w",
      subject: "Hi {{n}}",
      html: "<p>{{n}}</p>",
    });
    await call("GET", "/templates");
    await call("GET", "/templates/w?version=1");
    await call("PATCH", "/templates/w", { text: "x" });
    await call("POST", "/templates/w/preview", { variables: { n: 1 } });
    await call("DELETE", `/templates/${t["id"]}`);
    await call("POST", "/suppressions", { email: "x@example.test" });
    await call("GET", "/suppressions");
    await call("DELETE", "/suppressions/x%40example.test");
    await call("GET", "/doctor");
    await call("POST", "/domains/acme.test/rotate");
    await call("GET", "/ips");
    await call("GET", "/holds");
    await call("GET", "/queue");
    await call("POST", "/queue/suspensions", { target: "domain:example.test", reason: "r" });
    await call("DELETE", "/queue/suspensions/domain:example.test");
    await call("POST", "/queue/fail", { reason: "r", domain: "example.test", dry_run: true });
    await call("POST", "/queue/cancel", { reason: "r", domain: "example.test", dry_run: true });
    await call("GET", "/paths");
    await call("GET", "/health");

    await call("GET", "/projects");
    await call("POST", "/projects", {}, adminToken);
    const made = await call("POST", "/projects", { name: "shop" }, adminToken);
    await call("GET", "/projects", undefined, adminToken);
    await call("GET", `/projects/${made["id"]}`, undefined, adminToken);
    await call("PATCH", "/projects/shop", { per_day: 1000, suspended: true }, adminToken);
    const key = await call(
      "POST",
      "/projects/shop/keys",
      { name: "app", scope: "full" },
      adminToken,
    );
    const paused = await call(
      "POST",
      "/emails",
      { from: "a@shop.test", to: "b@example.test", subject: "s", text: "t" },
      key["token"] as string,
    );
    expect(paused["name"]).toBe("project_suspended");
    const refused = await call("GET", "/domains", undefined, adminToken);
    expect(refused["name"]).toBe("restricted_api_key");
    const shopDomains = await call("GET", "/domains", undefined, key["token"] as string);
    expect(shopDomains["data"]).toEqual([]);
    expect(await cli("domains", "list", "--project", "shop")).not.toContain("acme.test");
    expect(await cli("domains", "move", "acme.test", "shop")).toContain("now belongs to shop");
    const moved = await call("GET", "/domains", undefined, key["token"] as string);
    expect((moved["data"] as { name: string }[]).map((d) => d.name)).toEqual(["acme.test"]);
    await call("DELETE", "/projects/default", undefined, adminToken);
    await call("DELETE", "/projects/shop", undefined, adminToken);
    const again = await call("DELETE", "/projects/shop", undefined, adminToken);
    expect(again["deleted"]).toBe(true);
    const gone = await call("GET", "/domains", undefined, key["token"] as string);
    expect(gone["name"]).toBe("invalid_api_key");

    expect(problems).toEqual([]);
    const described = OPERATIONS.filter((o) => o.response && o.id !== "releaseHold").map(
      (o) => `${o.method} ${o.path} ok`,
    );
    expect(described.filter((x) => !seen.has(x))).toEqual([]);
  }, 60_000);
});
