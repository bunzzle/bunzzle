import { expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import { method, RpcClient, serveRpc } from "../../src/ipc/rpc.ts";
import { collect } from "../../src/metrics/metrics.ts";
import { RoleUsage } from "../../src/metrics/usage.ts";
import { b } from "../../src/validate/schema.ts";

const linux = await Bun.file("/proc/self/stat").exists();

test("every RPC server answers usage with its process CPU time on Linux", async () => {
  const dir = (await Bun.$`mktemp -d`.text()).trim();
  const server = await serveRpc(`${dir}/r.sock`, { ping: method(b.object({}), () => "pong") });
  const client = new RpcClient(`${dir}/r.sock`);
  try {
    const u = await client.call<{ cpuSeconds: number | null }>("usage", {});
    if (linux) expect(u.cpuSeconds).toBeGreaterThan(0);
    else expect(u.cpuSeconds).toBeNull();
  } finally {
    client.close();
    server.stop();
  }
});

test("roles that answered recently are up, the rest are down without a CPU sample", async () => {
  const dir = (await Bun.$`mktemp -d`.text()).trim();
  const server = await serveRpc(`${dir}/s.sock`, {});
  const signer = new RpcClient(`${dir}/s.sock`);
  const gone = new RpcClient(`${dir}/missing.sock`);
  let now = 1_000_000;
  const usage = new RoleUsage({
    targets: () => [
      { role: "signer", node: null, client: signer },
      { role: "delivery", node: "node-a", client: gone },
    ],
    pushed: ["api"],
    now: () => now,
    pollMs: 1_000,
  });
  try {
    await usage.poll();
    usage.report("api", 2.5);
    const at = (role: string) => usage.samples().find((s) => s.role === role);
    expect(at("core")).toMatchObject({ up: true });
    expect(at("signer")).toMatchObject({ node: null, up: true });
    expect(at("delivery")).toEqual({
      role: "delivery",
      node: "node-a",
      up: false,
      cpuSeconds: null,
    });
    expect(at("api")).toEqual({ role: "api", node: null, up: true, cpuSeconds: 2.5 });

    const families = collect(
      openDatabase({ path: ":memory:" }),
      null,
      [],
      0,
      0,
      undefined,
      null,
      null,
      null,
      usage.samples(),
    );
    const of = (name: string) => families.find((f) => f.name === name)?.samples ?? [];
    expect(of("bunzzle_role_up")).toContainEqual({
      labels: { role: "delivery", node: "node-a" },
      value: 0,
    });
    expect(of("bunzzle_role_cpu_seconds").map((s) => s.labels)).toEqual([
      ...(linux ? [{ role: "core" }, { role: "signer" }] : []),
      { role: "api" },
    ]);

    now += 4_000;
    expect(at("api")).toMatchObject({ up: false, cpuSeconds: 2.5 });
  } finally {
    signer.close();
    gone.close();
    server.stop();
  }
});
