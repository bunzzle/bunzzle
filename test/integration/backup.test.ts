import { afterAll, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const root = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-backup-${crypto.randomUUID()}`;
const master = generateMasterKey();
const env = {
  BUNZZLE_MASTER_KEY: master,
  BUNZZLE_DATA_DIR: `${root}/data`,
  BUNZZLE_KEYS_DIR: `${root}/keys`,
  BUNZZLE_RUN_DIR: `${root}/run`,
};
const servers: Served[] = [];

async function cli(extra: Record<string, string>, ...args: string[]) {
  const p = Bun.spawn(["bun", MAIN, ...args], {
    cwd: root,
    env: { PATH: Bun.env["PATH"] ?? "", ...env, ...extra },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(p.stdout).text(),
    new Response(p.stderr).text(),
    p.exited,
  ]);
  return { stdout, stderr, code };
}

async function newKey(): Promise<string> {
  const r = await cli({}, "keys", "create", "--name", "t", "--scope", "full");
  if (r.code !== 0) throw new Error(r.stderr);
  return (r.stdout.trim().split("\n").at(-1) ?? "").trim();
}

async function halt(s: Served) {
  s.proc.kill("SIGTERM");
  await s.proc.exited;
}

const domains = (s: Served, token: string) =>
  fetch(`${s.url}/domains`, { headers: { authorization: `Bearer ${token}` } }).then(
    (r) => r.status,
  );

afterAll(async () => {
  for (const s of servers) if (s.proc.exitCode === null) await halt(s);
  await Bun.$`rm -rf ${root}`.quiet();
});

test(
  "backup while running, restore after stopping, with the same master key only",
  async () => {
    await Bun.$`mkdir -p ${root}`.quiet();
    const first = await startServe(env);
    servers.push(first);
    const kept = await newKey();

    const b = await cli({}, "backup", "--to", `${root}/backup`);
    expect(b.code).toBe(0);
    expect(b.stdout).toContain("does not contain the master key");
    const manifest = (await Bun.file(`${root}/backup/manifest.json`).json()) as {
      master_key_id: string;
      files: { path: string }[];
    };
    expect(manifest.files.map((f) => f.path)).toContain("bunzzle.db");
    expect(manifest.files.map((f) => f.path)).toContain("keys/epochs.json");
    expect(manifest.master_key_id).toMatch(/^[0-9a-f]{16}$/);
    expect((await cli({}, "backup", "--to", `${root}/backup`)).stderr).toContain("not empty");

    const later = await newKey();
    expect((await cli({}, "restore", "--from", `${root}/backup`)).stderr).toContain(
      "stop `bunzzle serve`",
    );
    await halt(first);

    const wrong = await cli(
      { BUNZZLE_MASTER_KEY: generateMasterKey() },
      "restore",
      "--from",
      `${root}/backup`,
    );
    expect(wrong.code).not.toBe(0);
    expect(wrong.stderr).toContain("different master key");

    await Bun.$`cp -R ${root}/backup ${root}/tampered`.quiet();
    await Bun.write(`${root}/tampered/keys/epochs.json`, "{}");
    expect((await cli({}, "restore", "--from", `${root}/tampered`)).stderr).toContain(
      "changed since the backup",
    );

    const r = await cli({}, "restore", "--from", `${root}/backup`);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("before-restore-");

    const second = await startServe(env);
    servers.push(second);
    expect(await domains(second, kept)).toBe(200);
    expect(await domains(second, later)).toBe(403);
  },
  { timeout: 120_000 },
);
