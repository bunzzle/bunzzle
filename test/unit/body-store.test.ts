import { afterEach, describe, expect, test } from "bun:test";
import { BodyStore, BodyStoreError, decodeBody, encodeHead } from "../../src/core/store/bodies.ts";
import { openLibc } from "../../src/core/store/libc.ts";

const dirs: string[] = [];
const stores: BodyStore[] = [];

afterEach(async () => {
  for (const s of stores.splice(0)) s.close();
  for (const d of dirs.splice(0)) await Bun.$`chmod -R u+rwx ${d} && rm -rf ${d}`.quiet();
});

async function tempDir(): Promise<string> {
  const d = (await Bun.$`mktemp -d`.text()).trim();
  dirs.push(d);
  return d;
}

async function open(root: string): Promise<BodyStore> {
  const s = await BodyStore.open(root);
  stores.push(s);
  return s;
}

const ID = "0199c5a2-7d1e-7c3a-9b2f-4e8a1c6d3f7b";
const sealed = (size = 200 * 1024, epoch = 20_388) => ({
  epoch,
  wrapped: crypto.getRandomValues(new Uint8Array(92)),
  body: crypto.getRandomValues(new Uint8Array(size)),
});
const modeOf = async (path: string) => (await Bun.file(path).stat()).mode & 0o777;

describe("libc through bun:ffi", () => {
  test("creates, writes, syncs and removes a file", async () => {
    const dir = await tempDir();
    const libc = openLibc();
    const path = `${dir}/f`;
    const fd = libc.create(path, 0o600);
    expect(fd).toBeGreaterThanOrEqual(0);
    libc.writeAll(fd, new Uint8Array([1, 2, 3]), path);
    libc.syncData(fd, path);
    libc.close(fd);
    const dfd = libc.openRead(dir);
    libc.sync(dfd, dir);
    libc.close(dfd);
    expect(await Bun.file(path).bytes()).toEqual(new Uint8Array([1, 2, 3]));
    expect(await modeOf(path)).toBe(0o600);
    expect(libc.mkdir(`${dir}/d`, 0o700)).toBe(true);
    expect(libc.mkdir(`${dir}/d`, 0o700)).toBe(false);
    expect(libc.unlink(path)).toBe(true);
    expect(libc.unlink(path)).toBe(false);
  });

  test("reports the errno of a failed call", () => {
    expect(() => openLibc().create("/nonexistent-dir/x/y", 0o600)).toThrow(
      /create .* failed \(errno 2\)/,
    );
  });
});

describe("body file format", () => {
  test("round trip", () => {
    const b = sealed(1000);
    const head = encodeHead(b);
    const bytes = new Uint8Array(head.length + b.body.length);
    bytes.set(head);
    bytes.set(b.body, head.length);
    expect(decodeBody(bytes, b.epoch)).toEqual(b);
  });

  test("refuses a damaged file or another epoch", () => {
    const b = sealed(100);
    const head = encodeHead(b);
    const bytes = new Uint8Array([...head, ...b.body]);
    expect(() => decodeBody(bytes, b.epoch + 1)).toThrow(BodyStoreError);
    expect(() => decodeBody(bytes.subarray(0, 8), b.epoch)).toThrow(/no marker|short/);
    expect(() => decodeBody(bytes.subarray(0, 40), b.epoch)).toThrow(/short wrapped key/);
    const bad = bytes.slice();
    bad[0] = 0;
    expect(() => decodeBody(bad, b.epoch)).toThrow(/no marker/);
  });
});

describe("BodyStore", () => {
  test("writes a body under epoch and shard, readable after", async () => {
    const root = `${await tempDir()}/bodies`;
    const store = await open(root);
    const b = sealed();
    const size = await store.write(ID, b);
    const path = `${root}/${b.epoch}/7b/${ID}`;
    expect(store.path(ID, b.epoch)).toBe(path);
    expect(size).toBe((await Bun.file(path).stat()).size);
    expect(await modeOf(path)).toBe(0o600);
    expect(await modeOf(`${root}/${b.epoch}`)).toBe(0o700);
    expect(await modeOf(`${root}/${b.epoch}/7b`)).toBe(0o700);
    expect(await store.read(ID, b.epoch)).toEqual(b);
    expect(await Bun.file(`${root}/.probe`).exists()).toBe(false);
  });

  test("keeps the caller's bytes usable", async () => {
    const store = await open(`${await tempDir()}/bodies`);
    const b = sealed(1000);
    const copy = b.body.slice();
    await store.write(ID, b);
    expect(b.body).toEqual(copy);
  });

  test("writes many bodies at once", async () => {
    const store = await open(`${await tempDir()}/bodies`);
    const all = Array.from({ length: 200 }, () => ({ id: Bun.randomUUIDv7(), b: sealed(4096) }));
    await Promise.all(all.map(({ id, b }) => store.write(id, b)));
    for (const { id, b } of all) expect(await store.read(id, 20_388)).toEqual(b);
  });

  test("read of a missing body is null", async () => {
    const store = await open(`${await tempDir()}/bodies`);
    expect(await store.read(ID, 20_388)).toBeNull();
  });

  test("remove deletes the files it finds", async () => {
    const store = await open(`${await tempDir()}/bodies`);
    await store.write(ID, sealed(10));
    expect(
      await store.remove([
        { id: ID, epoch: 20_388 },
        { id: "missing-id", epoch: 20_388 },
      ]),
    ).toBe(1);
    expect(await store.read(ID, 20_388)).toBeNull();
  });

  test("refuses ids that are not plain names", async () => {
    const store = await open(`${await tempDir()}/bodies`);
    for (const id of ["../../etc/passwd", "a/b", "", "x", "a".repeat(65)])
      expect(() => store.path(id, 1)).toThrow(BodyStoreError);
    expect(() => store.path(ID, -1)).toThrow(BodyStoreError);
  });

  test("a failed write rejects and the store keeps working", async () => {
    const root = `${await tempDir()}/bodies`;
    const store = await open(root);
    await store.write(ID, sealed(10));
    await Bun.$`chmod 500 ${root}/20388/7b`.quiet();
    await expect(
      store.write("0199c5a2-7d1e-7c3a-9b2f-4e8a1c6d3f7b-2-7b", sealed(10)),
    ).rejects.toThrow(/body store: create .* failed/);
    await Bun.$`chmod 700 ${root}/20388/7b`.quiet();
    const other = "0199c5a2-7d1e-7c3a-9b2f-4e8a1c6d3fff";
    await store.write(other, sealed(10));
    expect(await store.read(other, 20_388)).not.toBeNull();
  });

  test("open fails when the store cannot be written", async () => {
    const dir = await tempDir();
    await Bun.write(`${dir}/file`, "x");
    await expect(BodyStore.open(`${dir}/file/bodies`)).rejects.toThrow(/body store: mkdir/);
    await Bun.$`mkdir ${dir}/ro && chmod 500 ${dir}/ro`.quiet();
    await expect(BodyStore.open(`${dir}/ro`)).rejects.toThrow(/body store: create/);
  });

  test("calls after close reject", async () => {
    const store = await BodyStore.open(`${await tempDir()}/bodies`);
    store.close();
    await expect(store.write(ID, sealed(10))).rejects.toThrow(/closed/);
  });

  test("a body is complete on disk once acked, even after kill -9", async () => {
    const root = `${await tempDir()}/bodies`;
    const script = `
      import { BodyStore } from ${JSON.stringify(`${import.meta.dir}/../../src/core/store/bodies.ts`)};
      const store = await BodyStore.open(${JSON.stringify(root)});
      const body = new Uint8Array(1024 * 1024);
      for (let i = 0; i < body.length; i += 65536) crypto.getRandomValues(body.subarray(i, i + 65536));
      await store.write(${JSON.stringify(ID)}, { epoch: 7, wrapped: new Uint8Array(92).fill(9), body });
      const digest = new Bun.CryptoHasher("sha256").update(body).digest("hex");
      console.log(digest);
      await new Promise(() => {});
    `;
    const child = Bun.spawn([process.execPath, "-e", script], {
      stdout: "pipe",
      stderr: "inherit",
    });
    const reader = child.stdout.getReader();
    let out = "";
    while (!out.includes("\n")) {
      const { value, done } = await reader.read();
      if (done) break;
      out += new TextDecoder().decode(value);
    }
    child.kill(9);
    await child.exited;
    const store = await open(root);
    const b = await store.read(ID, 7);
    expect(b?.wrapped).toEqual(new Uint8Array(92).fill(9));
    expect(new Bun.CryptoHasher("sha256").update(b?.body ?? new Uint8Array()).digest("hex")).toBe(
      out.trim(),
    );
  });
});
