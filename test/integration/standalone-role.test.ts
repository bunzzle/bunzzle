import { afterAll, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { RpcClient } from "../../src/ipc/rpc.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-standalone-${crypto.randomUUID()}`;
afterAll(async () => {
  await Bun.$`rm -rf ${dir}`.quiet();
});

test("a role started by a service manager reads the master key from a file", async () => {
  await Bun.$`mkdir -p ${dir}/run ${dir}/keys`.quiet();
  await Bun.write(`${dir}/master.key`, `${generateMasterKey()}\n`);
  const proc = Bun.spawn([process.execPath, "src/cli/main.ts", "role", "signer"], {
    env: {
      PATH: process.env["PATH"] ?? "",
      BUNZZLE_LOG_LEVEL: "error",
      BUNZZLE_RUN_DIR: `${dir}/run`,
      BUNZZLE_KEYS_DIR: `${dir}/keys`,
      BUNZZLE_MASTER_KEY_FILE: `${dir}/master.key`,
    },
    stdin: "ignore",
    stdout: "ignore",
    stderr: "pipe",
  });
  try {
    const sock = `${dir}/run/signer.sock`;
    const listening = () =>
      Bun.file(sock)
        .stat()
        .then((s) => s.isSocket())
        .catch(() => false);
    for (let i = 0; i < 100 && !(await listening()); i++) await Bun.sleep(100);
    const signer = new RpcClient(sock);
    const key = await signer.call<{ epoch: number }>("epochKey", {});
    expect(key.epoch).toBeGreaterThan(0);
    signer.close();
  } finally {
    proc.kill();
    await proc.exited;
  }
}, 30_000);

test("without a key on standard input or in a file the signer refuses to start", async () => {
  await Bun.$`mkdir -p ${dir}/run2 ${dir}/keys2`.quiet();
  const proc = Bun.spawn([process.execPath, "src/cli/main.ts", "role", "signer"], {
    env: {
      PATH: process.env["PATH"] ?? "",
      BUNZZLE_RUN_DIR: `${dir}/run2`,
      BUNZZLE_KEYS_DIR: `${dir}/keys2`,
    },
    stdin: "ignore",
    stdout: "ignore",
    stderr: "pipe",
  });
  expect(await proc.exited).not.toBe(0);
  expect(await new Response(proc.stderr).text()).toContain("BUNZZLE_MASTER_KEY_FILE");
});
