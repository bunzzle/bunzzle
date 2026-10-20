import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { alive, type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
let served: Served;

beforeAll(async () => {
  served = await startServe({ BUNZZLE_MASTER_KEY: generateMasterKey() });
}, 30_000);

afterAll(async () => {
  if (served.proc.exitCode === null) await served.stop();
});

describe("bunzzle serve", () => {
  test("runs six separate role processes", () => {
    expect([...served.pids.keys()].sort()).toEqual([
      "api",
      "core",
      "delivery",
      "dns",
      "inbound",
      "signer",
    ]);
    const pids = new Set(served.pids.values());
    expect(pids.size).toBe(6);
    expect(pids.has(served.proc.pid)).toBe(false);
    for (const pid of pids) expect(alive(pid)).toBe(true);
  });

  test("GET /health answers through core", async () => {
    const res = await fetch(`${served.url}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ ok: true, core: "ok" });
    expect(typeof body["version"]).toBe("string");
  });

  test("unknown routes return a JSON 404", async () => {
    const res = await fetch(`${served.url}/nope`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ statusCode: 404, name: "not_found", message: "Not found" });
  });

  test("creates the database, the key store and private directories", async () => {
    expect(await Bun.file(`${served.dir}/data/bunzzle.db`).exists()).toBe(true);
    expect(await Bun.file(`${served.dir}/keys/epochs.json`).exists()).toBe(true);
    const mode = async (p: string) => (await Bun.file(`${served.dir}/${p}`).stat()).mode & 0o777;
    expect(await mode("data")).toBe(0o700);
    expect(await mode("keys")).toBe(0o700);
    expect(await mode("run")).toBe(0o750);
    expect(await mode("keys/epochs.json")).toBe(0o600);
  });

  test("a killed role is restarted and health recovers", async () => {
    const before = served.pids.get("core") as number;
    process.kill(before, "SIGKILL");
    const end = Date.now() + 10_000;
    while (served.pids.get("core") === before && Date.now() < end) await Bun.sleep(20);
    const after = served.pids.get("core") as number;
    expect(after).not.toBe(before);
    expect(alive(after)).toBe(true);
    let ok = false;
    while (!ok && Date.now() < end) {
      ok = (await fetch(`${served.url}/health`)).status === 200;
      if (!ok) await Bun.sleep(20);
    }
    expect(ok).toBe(true);
  });

  test("SIGTERM stops every role and exits 0", async () => {
    const pids = [...served.pids.values()];
    expect(await served.stop()).toBe(0);
    for (const pid of pids) expect(alive(pid)).toBe(false);
  });
});

test("serve refuses to start without a master key", async () => {
  const proc = Bun.spawn(["bun", MAIN, "serve"], {
    env: { PATH: Bun.env["PATH"] ?? "", BUNZZLE_PORT: "0" },
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(await proc.exited).toBe(2);
  expect(await new Response(proc.stderr).text()).toContain("needs a master key");
});
