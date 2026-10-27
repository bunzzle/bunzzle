import type { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { DEFAULT_PROJECT } from "../../src/accounts/projects.ts";
import { recipientHasher } from "../../src/accounts/recipients.ts";
import { createLogger } from "../../src/core/log.ts";
import { BodyStore, BodyStoreError, type StoredBody } from "../../src/core/store/bodies.ts";
import { moveBodiesToFiles } from "../../src/core/store/bodies-move.ts";
import { emptyBodyTrash } from "../../src/core/store/body-trash.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { epochKeyPair, newEpochSeed } from "../../src/crypto/envelope.ts";
import { cancelEmail, enqueueEmail } from "../../src/delivery/queue.ts";
import { saveDomain } from "../../src/domains/domains.ts";
import type { RpcClient } from "../../src/ipc/rpc.ts";
import { coreMethods } from "../../src/roles/core-api.ts";
import { memoryBodies } from "../support/bodies.ts";

const T0 = Date.UTC(2026, 9, 27, 10, 0, 0);
const log = createLogger("error", {}, () => {});
const dirs: string[] = [];
const stores: BodyStore[] = [];

afterEach(async () => {
  for (const s of stores.splice(0)) s.close();
  for (const d of dirs.splice(0)) await Bun.$`rm -rf ${d}`.quiet();
});

async function store(): Promise<BodyStore> {
  const d = (await Bun.$`mktemp -d`.text()).trim();
  dirs.push(d);
  const s = await BodyStore.open(`${d}/bodies`);
  stores.push(s);
  return s;
}

const sealed = (epoch = 7, size = 1000): StoredBody => ({
  epoch,
  wrapped: crypto.getRandomValues(new Uint8Array(92)),
  body: crypto.getRandomValues(new Uint8Array(size)),
});

function email(db: Database, id: string, epoch = 7) {
  enqueueEmail(
    db,
    DEFAULT_PROJECT,
    {
      id,
      body: { epoch, size: 1 },
      from: "a@a.test",
      recipients: ["r@dest.test"],
      smtpUtf8: false,
      requireTls: false,
    },
    T0,
  );
}

function legacyRow(db: Database, id: string, b: StoredBody) {
  email(db, id, b.epoch);
  db.run("DELETE FROM body_files WHERE message_id = ?", [id]);
  db.run("DELETE FROM body_trash");
  db.run("INSERT INTO bodies (message_id, epoch, wrapped, body) VALUES (?, ?, ?, ?)", [
    id,
    b.epoch,
    b.wrapped,
    b.body,
  ]);
}

describe("exclusive create", () => {
  test("a second write of the same id is refused unless it replaces", async () => {
    const s = await store();
    const id = Bun.randomUUIDv7();
    const first = sealed();
    await s.write(id, first);
    const err = await s.write(id, sealed()).catch((e: BodyStoreError) => e);
    expect(err).toBeInstanceOf(BodyStoreError);
    expect((err as BodyStoreError).exists).toBe(true);
    expect(await s.read(id, 7)).toEqual(first);
    const second = sealed();
    await s.write(id, second, { replace: true });
    expect(await s.read(id, 7)).toEqual(second);
  });

  test("reads above the limit wait their turn", async () => {
    const d = (await Bun.$`mktemp -d`.text()).trim();
    dirs.push(d);
    const s = await BodyStore.open(`${d}/bodies`, { maxReads: 2 });
    stores.push(s);
    const all = Array.from({ length: 20 }, () => ({ id: Bun.randomUUIDv7(), b: sealed() }));
    for (const { id, b } of all) await s.write(id, b);
    const read = await Promise.all(all.map(({ id }) => s.read(id, 7)));
    expect(read).toEqual(all.map(({ b }) => b));
  });
});

describe("moving bodies out of the database", () => {
  test("moves every body, drops the old table, and a rerun does nothing", async () => {
    const db = openDatabase({ path: ":memory:" });
    const s = await store();
    const rows = Array.from({ length: 7 }, () => ({ id: Bun.randomUUIDv7(), b: sealed() }));
    for (const { id, b } of rows) legacyRow(db, id, b);
    expect(await moveBodiesToFiles(db, s, log, { batch: 3, free: async () => null })).toBe(7);
    for (const { id, b } of rows) {
      expect(await s.read(id, b.epoch)).toEqual(b);
      expect(db.query("SELECT size FROM body_files WHERE message_id = ?").get(id)).toEqual({
        size: 10 + 92 + 1000,
      });
    }
    expect(db.query("SELECT 1 FROM sqlite_master WHERE name = 'bodies'").get()).toBeNull();
    expect(db.query("SELECT count(*) AS n FROM body_trash").get()).toEqual({ n: 0 });
    expect(await moveBodiesToFiles(db, s, log)).toBe(0);
  });

  test("an interrupted move finishes on the next run", async () => {
    const db = openDatabase({ path: ":memory:" });
    const s = await store();
    const rows = Array.from({ length: 6 }, () => ({ id: Bun.randomUUIDv7(), b: sealed() }));
    for (const { id, b } of rows) legacyRow(db, id, b);
    let writes = 0;
    const flaky = {
      root: s.root,
      write: (id: string, b: StoredBody, o?: { replace?: boolean }) => {
        if (++writes > 4) return Promise.reject(new BodyStoreError("disk went away"));
        return s.write(id, b, o);
      },
    };
    const err = await moveBodiesToFiles(db, flaky, log, { batch: 2, free: async () => null }).catch(
      (e: Error) => e,
    );
    expect(err).toBeInstanceOf(BodyStoreError);
    expect(db.query("SELECT count(*) AS n FROM bodies").get()).toEqual({ n: 2 });
    expect(await moveBodiesToFiles(db, s, log, { batch: 2, free: async () => null })).toBe(2);
    for (const { id, b } of rows) expect(await s.read(id, b.epoch)).toEqual(b);
    expect(db.query("SELECT count(*) AS n FROM body_files").get()).toEqual({ n: 6 });
  });

  test("refuses to start without room for the bodies", async () => {
    const db = openDatabase({ path: ":memory:" });
    const s = await store();
    legacyRow(db, Bun.randomUUIDv7(), sealed(7, 3 * 1024 * 1024));
    await expect(
      moveBodiesToFiles(db, s, log, { minFreeMb: 100, free: async () => 50 }),
    ).rejects.toThrow(/needs 104 MB free, 50 MB is free/);
    expect(db.query("SELECT count(*) AS n FROM bodies").get()).toEqual({ n: 1 });
  });
});

describe("body trash", () => {
  test("a deleted row sends its file to the trash, emptied after the commit", async () => {
    const db = openDatabase({ path: ":memory:" });
    const writer = new Writer(db);
    const s = await store();
    const id = Bun.randomUUIDv7();
    await s.write(id, sealed());
    email(db, id);
    expect(cancelEmail(db, DEFAULT_PROJECT, id, T0)).toBe("ok");
    expect(db.query("SELECT epoch FROM body_trash WHERE message_id = ?").get(id)).toEqual({
      epoch: 7,
    });
    expect(await s.read(id, 7)).not.toBeNull();
    expect(await emptyBodyTrash(db, writer, s)).toBe(1);
    expect(await s.read(id, 7)).toBeNull();
    expect(db.query("SELECT count(*) AS n FROM body_trash").get()).toEqual({ n: 0 });
    expect(await emptyBodyTrash(db, writer, s)).toBe(0);
  });
});

describe("intake", () => {
  async function api(bodies = memoryBodies()) {
    const db = openDatabase({ path: ":memory:" });
    saveDomain(
      db,
      {
        project: DEFAULT_PROJECT,
        name: "a.test",
        status: "verified",
        mode: "records",
        records: [],
        createdAt: T0,
        checkedAt: null,
      },
      T0,
    );
    const epoch = await epochKeyPair(1, newEpochSeed());
    const stub = {
      call: async (m: string) => (m === "domains" ? ["a.test"] : null),
    } as unknown as RpcClient;
    const { methods } = coreMethods({
      bodies,
      db,
      writer: new Writer(db),
      log,
      signer: stub,
      delivery: stub,
      currentKey: async () => epoch,
      recipientHasher: async () => recipientHasher(new Uint8Array(32)),
      sourceIp: null,
    });
    const send = (extra: Record<string, unknown> = {}) =>
      methods["enqueue"]?.handle({
        project: DEFAULT_PROJECT,
        from: "a@a.test",
        recipients: ["r@dest.test"],
        data: "From: a@a.test\r\nTo: r@dest.test\r\nSubject: hi\r\n\r\nhi\r\n",
        smtpUtf8: false,
        requireTls: false,
        ...extra,
      }) as Promise<{ id: string; existed: boolean }>;
    return { db, bodies, send };
  }

  test("the body file is written before the row", async () => {
    const t = await api();
    const { id } = await t.send();
    expect(t.bodies.files.has(id)).toBe(true);
    expect(t.db.query("SELECT epoch FROM body_files WHERE message_id = ?").get(id)).toEqual({
      epoch: 1,
    });
  });

  test("a failed body write is a temporary error and leaves no row", async () => {
    const bodies = memoryBodies();
    bodies.write = () => Promise.reject(new BodyStoreError("body store: sync failed (errno 5)", 5));
    const t = await api(bodies);
    const id = Bun.randomUUIDv7();
    await expect(t.send({ id })).rejects.toMatchObject({ code: "unavailable" });
    expect(t.db.query("SELECT 1 FROM messages WHERE id = ?").get(id)).toBeNull();
    expect(t.db.query("SELECT 1 FROM body_files WHERE message_id = ?").get(id)).toBeNull();
  });

  test("a refused send removes the body it wrote", async () => {
    const t = await api();
    t.db.run("UPDATE projects SET per_hour = 0 WHERE id = ?", [DEFAULT_PROJECT]);
    const id = Bun.randomUUIDv7();
    await expect(t.send({ id })).rejects.toThrow();
    await Bun.sleep(0);
    expect(t.bodies.files.has(id)).toBe(false);
  });

  test("an idempotent repeat keeps the first body and removes its own", async () => {
    const t = await api();
    const first = await t.send({ idempotencyKey: "k1", bodyHash: "h" });
    const again = await t.send({ idempotencyKey: "k1", bodyHash: "h" });
    expect(again.id).toBe(first.id);
    await Bun.sleep(0);
    expect([...t.bodies.files.keys()]).toEqual([first.id]);
  });

  test("the same id while the first is still being accepted is a temporary error", async () => {
    const t = await api();
    const id = Bun.randomUUIDv7();
    await t.bodies.write(id, sealed(1));
    await expect(t.send({ id })).rejects.toMatchObject({ code: "unavailable" });
    expect(t.bodies.files.has(id)).toBe(true);
  });
});
