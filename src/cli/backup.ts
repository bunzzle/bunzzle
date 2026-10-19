import { Database } from "bun:sqlite";
import type { Config } from "../config.ts";
import { readMasterKeyText } from "../crypto/load.ts";
import { masterKeyFrom } from "../crypto/master.ts";
import { privateDir } from "../roles/runtime.ts";
import { sockets } from "../roles/wire.ts";
import { runDirOf } from "./admin.ts";
import { parseArgs, UsageError } from "./args.ts";

interface Entry {
  path: string;
  size: number;
  sha256: string;
}

interface Manifest {
  format: 1;
  created_at: string;
  master_key_id: string | null;
  files: Entry[];
}

const DB = "bunzzle.db";

async function digest(path: string): Promise<{ size: number; sha256: string }> {
  const bytes = await Bun.file(path).bytes();
  const h = new Bun.CryptoHasher("sha256");
  h.update(bytes);
  return { size: bytes.length, sha256: h.digest("hex") };
}

async function keyFiles(dir: string): Promise<string[]> {
  const all = await Array.fromAsync(
    new Bun.Glob("**/*.json").scan({ cwd: dir, onlyFiles: true }),
  ).catch(() => [] as string[]);
  return all.sort();
}

function parentOf(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i);
}

async function masterIdOf(dir: string, files: string[]): Promise<string | null> {
  for (const f of files) {
    const data = (await Bun.file(`${dir}/${f}`)
      .json()
      .catch(() => null)) as { masterKeyId?: unknown } | null;
    if (typeof data?.masterKeyId === "string") return data.masterKeyId;
  }
  return null;
}

async function running(config: Config): Promise<boolean> {
  const path = sockets(await runDirOf(config)).core;
  try {
    const s = await Bun.connect({ unix: path, socket: { data() {} } });
    s.end();
    return true;
  } catch {
    return false;
  }
}

async function isEmptyDir(dir: string): Promise<boolean> {
  const any = await Array.fromAsync(new Bun.Glob("*").scan({ cwd: dir, dot: true })).catch(
    () => [] as string[],
  );
  return any.length === 0;
}

export async function backup(config: Config, to: string): Promise<Manifest> {
  if (!(await Bun.file(config.dbPath).exists())) {
    throw new UsageError(`no database at ${config.dbPath}: nothing to back up`);
  }
  if (!(await isEmptyDir(to))) throw new UsageError(`${to} is not empty`);
  await privateDir(`${to}/keys`);
  const db = new Database(config.dbPath, { readonly: true });
  try {
    db.query("VACUUM INTO ?").run(`${to}/${DB}`);
  } finally {
    db.close();
  }
  const keys = await keyFiles(config.keysDir);
  for (const f of keys) {
    await privateDir(`${to}/keys/${parentOf(f)}`);
    await Bun.write(`${to}/keys/${f}`, Bun.file(`${config.keysDir}/${f}`));
  }
  const files: Entry[] = [];
  for (const rel of [DB, ...keys.map((k) => `keys/${k}`)]) {
    const { size, sha256 } = await digest(`${to}/${rel}`);
    files.push({ path: rel, size, sha256 });
  }
  const manifest: Manifest = {
    format: 1,
    created_at: new Date().toISOString(),
    master_key_id: await masterIdOf(config.keysDir, keys),
    files,
  };
  await Bun.write(`${to}/manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`);
  await Bun.$`chmod -R go-rwx ${to}`.quiet();
  return manifest;
}

export async function restore(config: Config, from: string, now = new Date()): Promise<string> {
  const manifest = (await Bun.file(`${from}/manifest.json`)
    .json()
    .catch(() => null)) as Manifest | null;
  if (manifest?.format !== 1 || !Array.isArray(manifest.files)) {
    throw new UsageError(`${from} has no valid manifest.json`);
  }
  for (const e of manifest.files) {
    if (e.path.startsWith("/") || e.path.split("/").includes("..")) {
      throw new UsageError(`unsafe path in the manifest: ${e.path}`);
    }
    const got = await digest(`${from}/${e.path}`).catch(() => null);
    if (!got || got.sha256 !== e.sha256) {
      throw new UsageError(`${e.path} is missing or changed since the backup was made`);
    }
  }
  const text = await readMasterKeyText(config);
  if (!text) {
    throw new UsageError(
      "restore needs the master key: set BUNZZLE_MASTER_KEY or BUNZZLE_MASTER_KEY_FILE",
    );
  }
  const master = await masterKeyFrom(text);
  if (manifest.master_key_id !== null && manifest.master_key_id !== master.id) {
    throw new UsageError(
      "this backup was made with a different master key; set the master key it was made with",
    );
  }
  if (await running(config)) throw new UsageError("stop `bunzzle serve` before restoring");
  const aside = `${config.dataDir.replace(/\/+$/, "")}/before-restore-${now.toISOString().replace(/[:.]/g, "-")}`;
  await privateDir(`${aside}/keys`);
  for (const suffix of ["", "-wal", "-shm"]) {
    const p = `${config.dbPath}${suffix}`;
    if (await Bun.file(p).exists()) await Bun.$`mv ${p} ${aside}/`.quiet();
  }
  for (const f of await keyFiles(config.keysDir)) {
    await privateDir(`${aside}/keys/${parentOf(f)}`);
    await Bun.$`mv ${`${config.keysDir}/${f}`} ${`${aside}/keys/${f}`}`.quiet();
  }
  await privateDir(config.dataDir);
  await privateDir(config.keysDir);
  for (const e of manifest.files) {
    const target = e.path === DB ? config.dbPath : `${config.keysDir}/${e.path.slice(5)}`;
    await privateDir(parentOf(target));
    await Bun.write(target, Bun.file(`${from}/${e.path}`));
  }
  await Bun.$`chmod -R go-rwx ${config.keysDir} ${config.dbPath}`.quiet();
  return aside;
}

export async function backupCommand(argv: string[], config: Config) {
  const args = parseArgs(argv, { strings: ["to"] });
  const to = args.strings.get("to");
  if (!to) throw new UsageError("usage: bunzzle backup --to DIR");
  const m = await backup(config, to.replace(/\/+$/, ""));
  const size = m.files.reduce((n, f) => n + f.size, 0);
  console.log(`backup written to ${to}: ${m.files.length} files, ${size} bytes`);
  console.log(
    "It does not contain the master key. Keep the master key somewhere else: without it the backup cannot be read.",
  );
}

export async function restoreCommand(argv: string[], config: Config) {
  const args = parseArgs(argv, { strings: ["from"] });
  const from = args.strings.get("from");
  if (!from) throw new UsageError("usage: bunzzle restore --from DIR");
  const aside = await restore(config, from.replace(/\/+$/, ""));
  console.log(`restored from ${from}. The files it replaced are in ${aside}.`);
}
