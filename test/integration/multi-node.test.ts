import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { Subprocess } from "bun";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { onThisMachine } from "../../src/ips/local.ts";
import { type FakeDns, startFakeDns, type Zone } from "../support/fake-dns.ts";
import { type FakeMx, startFakeMx } from "../support/fake-mx.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const ROOT = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-nodes-${crypto.randomUUID()}`;
const CORE = `${ROOT}/core`;
const NODES = [
  { name: "node-a", ip: "127.0.0.2", pool: "a", domain: "a.test" },
  { name: "node-b", ip: "127.0.0.3", pool: "b", domain: "b.test" },
];
const usable = (await Promise.all(NODES.map((n) => onThisMachine(n.ip)))).every(Boolean);

const zone: Zone = {
  "inbox.test": { MX: [[10, "mx.inbox.test"]] },
  "mx.inbox.test": { A: ["127.0.0.1"] },
};
let dns: FakeDns;
let mx: FakeMx;
let api = "";
let token = "";
const procs = new Map<string, Subprocess>();

function freePort(): number {
  const s = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
  const port = s.port;
  s.stop(true);
  return port;
}

let explain: () => Promise<string> = async () => "";

async function waitFor(what: string, ok: () => Promise<boolean> | boolean, ms = 20_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await ok()) return;
    await Bun.sleep(100);
  }
  throw new Error(`timed out waiting for ${what}\n${await explain().catch((e) => String(e))}`);
}

const exists = (path: string) =>
  Bun.file(path)
    .stat()
    .then(() => true)
    .catch(() => false);

function baseEnv(): Record<string, string> {
  return {
    PATH: Bun.env["PATH"] ?? "",
    HOME: Bun.env["HOME"] ?? "",
    TMPDIR: Bun.env["TMPDIR"] ?? "/tmp",
    BUNZZLE_LOG_LEVEL: "info",
    BUNZZLE_DNS_SERVERS: `127.0.0.1:${dns.port}`,
    BUNZZLE_SMTP_PORT: String(mx.port),
    BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "true",
  };
}

let coreEnv: Record<string, string> = {};

async function cli(cwd: string, env: Record<string, string>, ...args: string[]) {
  const p = Bun.spawn(["bun", MAIN, ...args], { cwd, env, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([
    new Response(p.stdout).text(),
    new Response(p.stderr).text(),
    p.exited,
  ]);
  if (code !== 0) throw new Error(`bunzzle ${args.join(" ")} exited ${code}: ${err || out}`);
  return out.trim();
}

async function startRole(key: string, role: string, cwd: string, env: Record<string, string>) {
  const proc = Bun.spawn(["bun", MAIN, "role", role], {
    cwd,
    env,
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
  procs.set(key, proc);
  return proc;
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${api}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const json = (await r.json()) as T;
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${JSON.stringify(json)}`);
  return json;
}

interface NodeView {
  name: string;
  up: boolean;
  ips: string[];
  delivered: number;
}

const nodes = async () => (await call<{ data: NodeView[] }>("GET", "/nodes")).data;
const nodeView = async (name: string) => (await nodes()).find((n) => n.name === name);

async function send(domain: string, subject: string): Promise<string> {
  const { id } = await call<{ id: string }>("POST", "/emails", {
    from: `hello@${domain}`,
    to: ["someone@inbox.test"],
    subject,
    text: "through a delivery node",
  });
  sent.push(id);
  return id;
}

const status = async (id: string) =>
  (await call<{ last_event: string }>("GET", `/emails/${id}`)).last_event;

const sent: string[] = [];

const received = () =>
  mx.sessions.flatMap((s) =>
    s.messages.map((m) => ({
      remote: s.remote.replace(/^::ffff:/, ""),
      subject: /^Subject: (.*)$/m.exec(m)?.[1]?.trim() ?? "",
      ehlo: s.commands.find((c) => /^EHLO /i.test(c))?.slice(5) ?? "",
    })),
  );

beforeAll(async () => {
  if (!usable) return;
  explain = async () =>
    JSON.stringify(
      {
        nodes: await nodes(),
        emails: await Promise.all(sent.map((id) => call("GET", `/emails/${id}`))),
        received: received(),
      },
      null,
      1,
    );
  dns = await startFakeDns(zone);
  mx = startFakeMx({ finalDelayMs: 400 });
  const apiPort = freePort();
  api = `http://127.0.0.1:${apiPort}`;
  await Bun.$`mkdir -p ${CORE}/run ${CORE}/data ${CORE}/keys && chmod 700 ${CORE}/data ${CORE}/keys`.quiet();
  await Bun.write(`${CORE}/master.key`, `${generateMasterKey()}\n`);
  coreEnv = {
    ...baseEnv(),
    BUNZZLE_MASTER_KEY_FILE: `${CORE}/master.key`,
    BUNZZLE_EHLO_NAME: "core.bunzzle.test",
    BUNZZLE_SOURCE_IPS: NODES.map((n) => `${n.ip}=${n.pool}`).join(","),
    BUNZZLE_ESTABLISHED_IPS: NODES.map((n) => n.ip).join(","),
    BUNZZLE_RETRY_SCALE: "0.001",
    BUNZZLE_HOST: "127.0.0.1",
    BUNZZLE_PORT: String(apiPort),
  };
  await startRole("signer", "signer", CORE, coreEnv);
  await waitFor("signer", () => exists(`${CORE}/run/signer.sock`));
  await startRole("dns", "dns", CORE, coreEnv);
  await waitFor("dns", () => exists(`${CORE}/run/dns.sock`));
  await startRole("link", "link", CORE, coreEnv);
  await waitFor("link", () => exists(`${CORE}/run/link.sock`));
  await startRole("delivery", "delivery", CORE, { ...coreEnv, BUNZZLE_SOURCE_IPS: "" });
  await waitFor("local delivery", () => exists(`${CORE}/run/delivery.sock`));
  await startRole("core", "core", CORE, coreEnv);
  await waitFor("core", () => exists(`${CORE}/run/admin.sock`));
  await startRole("api", "api", CORE, coreEnv);
  await waitFor("api", () =>
    fetch(`${api}/health`)
      .then((r) => r.ok)
      .catch(() => false),
  );

  for (const n of NODES) {
    const dir = `${ROOT}/${n.name}`;
    await Bun.$`mkdir -p ${dir}/run`.quiet();
    const port = freePort();
    const env = {
      ...baseEnv(),
      BUNZZLE_RUN_DIR: `${dir}/run`,
      BUNZZLE_NODE_DIR: `${dir}/node`,
      BUNZZLE_DELIVERY_LISTEN: `127.0.0.1:${port}`,
      BUNZZLE_SOURCE_IPS: n.ip,
      BUNZZLE_EHLO_NAME: `${n.name}.bunzzle.test`,
    };
    await cli(dir, env, "nodes", "request", n.name);
    await cli(
      CORE,
      coreEnv,
      "nodes",
      "add",
      n.name,
      `127.0.0.1:${port}`,
      `${dir}/node/request.csr`,
      "--out",
      `${dir}/bundle.json`,
    );
    await cli(dir, env, "nodes", "install", `${dir}/bundle.json`);
    await startRole(n.name, "delivery", dir, env);
    await waitFor(n.name, () => exists(`${dir}/run/delivery.sock`));
  }

  token = (
    await cli(
      CORE,
      coreEnv,
      "keys",
      "create",
      "--name",
      "app",
      "--scope",
      "full",
      "--rate-limit",
      "10000",
    )
  )
    .split("\n")
    .at(-1) as string;
  for (const n of NODES) {
    const domain = await call<{ records: { record: string; name: string; value: string }[] }>(
      "POST",
      "/domains",
      { name: n.domain },
    );
    for (const r of domain.records.filter((x) => x.record === "DKIM")) {
      zone[r.name] = { TXT: [r.value] };
    }
    await call("POST", `/domains/${n.domain}/verify`);
  }
}, 90_000);

afterAll(async () => {
  for (const p of procs.values()) p.kill();
  await Promise.all([...procs.values()].map((p) => p.exited));
  dns?.stop();
  mx?.stop();
  await Bun.$`rm -rf ${ROOT}`.quiet();
});

describe.skipIf(!usable)("one core and two delivery nodes", () => {
  test("core reaches both nodes and learns the IP each one has", async () => {
    await waitFor("both nodes up", async () => {
      const list = await nodes();
      return NODES.every((n) =>
        list.some((v) => v.name === n.name && v.up && v.ips.includes(n.ip)),
      );
    });
    expect((await nodeView("local"))?.ips).toEqual([]);
  }, 60_000);

  test("mail goes out from each node's own IP", async () => {
    for (const n of NODES) await call("PATCH", `/domains/${n.domain}`, { ip_pool: n.pool });
    const ids = await Promise.all(
      NODES.flatMap((n) => [1, 2, 3].map((i) => send(n.domain, `spread ${n.name} ${i}`))),
    );
    await waitFor("6 delivered", async () =>
      (await Promise.all(ids.map(status))).every((s) => s === "delivered"),
    );
    for (const n of NODES) {
      const mine = received().filter((r) => r.subject.startsWith(`spread ${n.name} `));
      expect(mine.length).toBe(3);
      expect(mine.every((r) => r.remote === n.ip && r.ehlo === `${n.name}.bunzzle.test`)).toBe(
        true,
      );
      expect((await nodeView(n.name))?.delivered).toBe(3);
    }
  }, 60_000);

  test("a node stopped during a batch loses no mail: the rest goes out through the other node", async () => {
    for (const n of NODES) await call("PATCH", `/domains/${n.domain}`, { ip_pool: null });
    const ids: string[] = [];
    for (let i = 0; i < 20; i++) ids.push(await send("a.test", `batch ${i}`));
    const batch = () => received().filter((r) => r.subject.startsWith("batch "));
    await waitFor("the batch to start on node-a", () => batch().length >= 2);
    procs.get("node-a")?.kill(9);
    await waitFor(
      "all 20 delivered",
      async () => (await Promise.all(ids.map(status))).every((s) => s === "delivered"),
      60_000,
    );
    const subjects = new Set(batch().map((r) => r.subject));
    expect([...Array(20).keys()].every((i) => subjects.has(`batch ${i}`))).toBe(true);
    expect(batch().some((r) => r.remote === "127.0.0.2")).toBe(true);
    expect(batch().some((r) => r.remote === "127.0.0.3")).toBe(true);
    await waitFor("node-a down", async () => (await nodeView("node-a"))?.up === false);
  }, 90_000);
});
