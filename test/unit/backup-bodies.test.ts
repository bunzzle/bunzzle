import { Database } from "bun:sqlite";
import { afterEach, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { backup, restore } from "../../src/cli/backup.ts";
import { loadConfig } from "../../src/config.ts";
import { BodyStore, type StoredBody } from "../../src/core/store/bodies.ts";
import { sweepBodyFiles } from "../../src/core/store/body-sweep.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { enqueueEmail } from "../../src/delivery/queue.ts";

const dirs: string[] = [];
const stores: BodyStore[] = [];

afterEach(async () => {
  for (const s of stores.splice(0)) s.close();
  for (const d of dirs.splice(0)) await Bun.$`rm -rf ${d}`.quiet();
});

async function setup() {
  const root = (await Bun.$`mktemp -d`.text()).trim();
  dirs.push(root);
  const config = loadConfig({
    BUNZZLE_DATA_DIR: `${root}/data`,
    BUNZZLE_KEYS_DIR: `${root}/keys`,
    BUNZZLE_RUN_DIR: `${root}/run`,
    BUNZZLE_MASTER_KEY: generateMasterKey(),
  });
  await Bun.$`mkdir -p ${root}/data ${root}/keys ${root}/run`.quiet();
  const db = openDatabase({ path: config.dbPath });
  const store = await BodyStore.open(config.bodiesDir);
  stores.push(store);
  const add = async (epoch = 20_388) => {
    const id = Bun.randomUUIDv7();
    const b: StoredBody = {
      epoch,
      wrapped: crypto.getRandomValues(new Uint8Array(92)),
      body: crypto.getRandomValues(new Uint8Array(5000)),
    };
    const size = await store.write(id, b);
    enqueueEmail(
      db,
      DEFAULT_PROJECT,
      {
        id,
        body: { epoch, size },
        from: "a@a.test",
        recipients: ["r@dest.test"],
        smtpUtf8: false,
        requireTls: false,
      },
      Date.now(),
    );
    return { id, b };
  };
  return { root, config, db, store, add };
}

test("backup copies body files with sums, restore puts them back", async () => {
  const t = await setup();
  const bodies = [await t.add(), await t.add(), await t.add(20_300)];
  t.db.close();

  const to = `${t.root}/backup`;
  const m = await backup(t.config, to);
  expect(m.format).toBe(2);
  expect(m.files.map((f) => f.path)).toContain("bodies.sha256");
  const sums = (await Bun.file(`${to}/bodies.sha256`).text()).trim().split("\n");
  expect(sums.length).toBe(3);
  for (const { id } of bodies) {
    expect(sums.some((l) => l.endsWith(`/${id}`))).toBe(true);
  }

  await Bun.$`rm -rf ${t.config.bodiesDir}`.quiet();
  const aside = await restore(t.config, to);
  expect(aside).toContain("before-restore-");
  const after = await BodyStore.open(t.config.bodiesDir);
  stores.push(after);
  for (const { id, b } of bodies) expect(await after.read(id, b.epoch)).toEqual(b);
});

test("a body removed between the snapshot and the copy leaves the backup consistent", async () => {
  const t = await setup();
  const kept = await t.add();
  const lost = await t.add();
  t.db.close();
  await Bun.$`rm ${t.store.path(lost.id, lost.b.epoch)}`.quiet();

  const to = `${t.root}/backup`;
  await backup(t.config, to);
  const snap = new Database(`${to}/bunzzle.db`, { readonly: true });
  const ids = snap
    .query<{ message_id: string }, []>("SELECT message_id FROM body_files")
    .all()
    .map((r) => r.message_id);
  expect(ids).toEqual([kept.id]);
  expect(snap.query("SELECT count(*) AS n FROM body_trash").get()).toEqual({ n: 0 });
  snap.close();
  expect((await Bun.file(`${to}/bodies.sha256`).text()).trim().split("\n").length).toBe(1);
});

test("restore refuses a changed body file or an unsafe path", async () => {
  const t = await setup();
  const { id, b } = await t.add();
  t.db.close();
  const to = `${t.root}/backup`;
  await backup(t.config, to);
  const rel = t.store.path(id, b.epoch).slice(t.config.bodiesDir.length + 1);

  await Bun.$`cp -R ${to} ${t.root}/changed`.quiet();
  await Bun.write(`${t.root}/changed/bodies/${rel}`, "x");
  expect(String(await restore(t.config, `${t.root}/changed`).catch((e: Error) => e))).toContain(
    "changed since the backup",
  );

  await Bun.$`cp -R ${to} ${t.root}/unsafe`.quiet();
  const sums = await Bun.file(`${to}/bodies.sha256`).text();
  await Bun.write(
    `${t.root}/unsafe/bodies.sha256`,
    sums.replace(`bodies/${rel}`, "bodies/1/00/../../../keys"),
  );
  const manifest = (await Bun.file(`${to}/manifest.json`).json()) as {
    files: { path: string; sha256: string; size: number }[];
  };
  const text = await Bun.file(`${t.root}/unsafe/bodies.sha256`).text();
  const entry = manifest.files.find((f) => f.path === "bodies.sha256");
  if (entry) {
    entry.sha256 = new Bun.CryptoHasher("sha256").update(text).digest("hex");
    entry.size = new TextEncoder().encode(text).length;
  }
  await Bun.write(`${t.root}/unsafe/manifest.json`, JSON.stringify(manifest));
  expect(String(await restore(t.config, `${t.root}/unsafe`).catch((e: Error) => e))).toContain(
    "unsafe body path",
  );
});

test("the sweep removes old files without a row and keeps the rest", async () => {
  const t = await setup();
  const live = await t.add(100);
  const orphan = Bun.randomUUIDv7();
  await t.store.write(orphan, { epoch: 100, wrapped: new Uint8Array(1), body: new Uint8Array(1) });
  const recent = Bun.randomUUIDv7();
  await t.store.write(recent, { epoch: 200, wrapped: new Uint8Array(1), body: new Uint8Array(1) });
  const gone = Bun.randomUUIDv7();
  await t.store.write(gone, { epoch: 50, wrapped: new Uint8Array(1), body: new Uint8Array(1) });

  const swept = await sweepBodyFiles(t.db, t.store, 150);
  expect(swept.removed).toBe(2);
  expect(await t.store.read(live.id, 100)).toEqual(live.b);
  expect(await t.store.read(orphan, 100)).toBeNull();
  expect(await t.store.read(recent, 200)).not.toBeNull();
  expect(
    (
      await Array.fromAsync(new Bun.Glob("*").scan({ cwd: t.config.bodiesDir, onlyFiles: false }))
    ).sort(),
  ).toEqual(["100", "200"]);
  t.db.close();
});
