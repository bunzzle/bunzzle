import { afterAll, expect, test } from "bun:test";
import { createResolver } from "../../src/dns/resolver.ts";
import { RpcClient } from "../../src/ipc/rpc.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-ns-${crypto.randomUUID()}`;
afterAll(async () => {
  await Bun.$`rm -rf ${dir}`.quiet();
});

async function start(): Promise<{ proc: Bun.Subprocess; port: number }> {
  const { promise, resolve } = Promise.withResolvers<number>();
  const proc = Bun.spawn([process.execPath, "src/cli/main.ts", "role", "ns"], {
    env: {
      PATH: Bun.env["PATH"] ?? "",
      BUNZZLE_LOG_LEVEL: "error",
      BUNZZLE_RUN_DIR: `${dir}/run`,
      BUNZZLE_DATA_DIR: `${dir}/data`,
      BUNZZLE_NS_ZONE: "dz.mail.test",
      BUNZZLE_NS_NAMES: "ns1.mail.test",
      BUNZZLE_NS_LISTEN: "127.0.0.1",
      BUNZZLE_NS_PORT: "0",
    },
    stdin: "ignore",
    stdout: "ignore",
    stderr: "inherit",
    ipc(message) {
      const m = message as { type?: string; ports?: number[] };
      if (m.type === "ready") resolve(m.ports?.[0] ?? 0);
    },
  });
  return { proc, port: await promise };
}

test("the ns role serves a pushed zone and keeps it across a restart", async () => {
  await Bun.$`mkdir -p ${dir}/run`.quiet();
  const first = await start();
  try {
    const resolver = createResolver({
      servers: [{ host: "127.0.0.1", port: first.port }],
      timeoutMs: 1000,
      attempts: 1,
    });
    const before = await resolver.query("_check.dz.mail.test", "TXT");
    expect(before.rcode).toBe(2);
    const rpc = new RpcClient(`${dir}/run/ns.sock`);
    await expect(
      rpc.call("zone", {
        serial: 1,
        records: [{ name: "x.example.com", type: "TXT", ttl: 300, value: "no" }],
      }),
    ).rejects.toThrow(/outside the zone/);
    await rpc.call("zone", {
      serial: 42,
      records: [{ name: "_check.dz.mail.test", type: "TXT", ttl: 300, value: "42" }],
    });
    const after = await resolver.query("_check.dz.mail.test", "TXT");
    expect(after.records[0]?.type === "TXT" && after.records[0].strings).toEqual(["42"]);
    const stats = await rpc.call<{ serial: number }>("stats", {});
    expect(stats.serial).toBe(42);
    rpc.close();
  } finally {
    first.proc.kill();
    await first.proc.exited;
  }

  const second = await start();
  try {
    const resolver = createResolver({
      servers: [{ host: "127.0.0.1", port: second.port }],
      timeoutMs: 1000,
    });
    const again = await resolver.query("_check.dz.mail.test", "TXT");
    expect(again.records[0]?.type === "TXT" && again.records[0].strings).toEqual(["42"]);
  } finally {
    second.proc.kill();
    await second.proc.exited;
  }
}, 30_000);
