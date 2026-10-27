import type { BodyJob, BodyReply } from "./body-worker.ts";
import { EEXIST } from "./libc.ts";

export interface StoredBody {
  epoch: number;
  wrapped: Uint8Array;
  body: Uint8Array;
}

type JobInput = BodyJob extends infer J ? (J extends BodyJob ? Omit<J, "seq"> : never) : never;

const MAGIC = new TextEncoder().encode("BZB1");
const FIXED = MAGIC.length + 4 + 2;
const ID = /^[A-Za-z0-9._-]{1,64}$/;
const WORKER = Bun.main.startsWith("/$bunfs/")
  ? "/$bunfs/root/core/store/body-worker.js"
  : new URL("./body-worker.ts", import.meta.url).href;

export class BodyStoreError extends Error {
  override name = "BodyStoreError";
  constructor(
    message: string,
    readonly errno: number | null = null,
  ) {
    super(message);
  }

  get exists(): boolean {
    return this.errno === EEXIST;
  }
}

export function encodeHead(b: StoredBody): Uint8Array {
  if (b.wrapped.length > 0xffff) throw new BodyStoreError("wrapped key is too long");
  const head = new Uint8Array(FIXED + b.wrapped.length);
  head.set(MAGIC);
  const view = new DataView(head.buffer);
  view.setUint32(MAGIC.length, b.epoch);
  view.setUint16(MAGIC.length + 4, b.wrapped.length);
  head.set(b.wrapped, FIXED);
  return head;
}

export function decodeBody(bytes: Uint8Array, epoch: number): StoredBody {
  const bad = (why: string) => new BodyStoreError(`body file is damaged: ${why}`);
  if (bytes.length < FIXED || !MAGIC.every((m, i) => bytes[i] === m)) throw bad("no marker");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stored = view.getUint32(MAGIC.length);
  if (stored !== epoch) throw bad(`epoch ${stored}, expected ${epoch}`);
  const end = FIXED + view.getUint16(MAGIC.length + 4);
  if (end > bytes.length) throw bad("short wrapped key");
  return { epoch, wrapped: bytes.subarray(FIXED, end), body: bytes.subarray(end) };
}

export interface BodyFiles {
  write(id: string, b: StoredBody, o?: { replace?: boolean }): Promise<number>;
  read(id: string, epoch: number): Promise<StoredBody | null>;
  remove(bodies: { id: string; epoch: number }[]): Promise<number>;
}

export class BodyStore implements BodyFiles {
  readonly root: string;
  readonly #worker: Worker;
  readonly #pending = new Map<number, PromiseWithResolvers<number>>();
  #seq = 0;
  #broken: string | null = null;
  readonly #maxReads: number;
  #reading = 0;
  readonly #waiting: (() => void)[] = [];

  private constructor(root: string, maxReads: number) {
    this.root = root;
    this.#maxReads = maxReads;
    this.#worker = new Worker(WORKER);
    this.#worker.onmessage = (e: MessageEvent<BodyReply>) => {
      const r = e.data;
      const p = this.#pending.get(r.seq);
      if (!p) return;
      this.#pending.delete(r.seq);
      if (r.ok) p.resolve(r.value);
      else p.reject(new BodyStoreError(r.error, r.errno));
    };
    this.#worker.onerror = (e) => this.#fail(`body store worker stopped: ${e.message}`);
  }

  static async open(
    root: string,
    { maxReads = 64 }: { maxReads?: number } = {},
  ): Promise<BodyStore> {
    const store = new BodyStore(root.replace(/\/+$/, ""), maxReads);
    try {
      await store.#send({ op: "probe", root: store.root });
    } catch (err) {
      store.close();
      throw err;
    }
    return store;
  }

  path(id: string, epoch: number): string {
    if (!ID.test(id) || id === "." || id === "..")
      throw new BodyStoreError(`not a valid message id: ${id}`);
    if (!Number.isSafeInteger(epoch) || epoch < 0)
      throw new BodyStoreError(`not an epoch: ${epoch}`);
    const shard = (Bun.hash.crc32(id) & 0xff).toString(16).padStart(2, "0");
    return `${this.root}/${epoch}/${shard}/${id}`;
  }

  write(
    id: string,
    b: StoredBody,
    { replace = false }: { replace?: boolean } = {},
  ): Promise<number> {
    const path = this.path(id, b.epoch);
    const epochDir = `${this.root}/${b.epoch}`;
    return this.#send({
      op: "write",
      dirs: [epochDir, path.slice(0, path.lastIndexOf("/"))],
      path,
      head: encodeHead(b),
      body: b.body.slice(),
      replace,
    });
  }

  async read(id: string, epoch: number): Promise<StoredBody | null> {
    const file = Bun.file(this.path(id, epoch));
    while (this.#reading >= this.#maxReads) {
      const turn = Promise.withResolvers<void>();
      this.#waiting.push(turn.resolve);
      await turn.promise;
    }
    this.#reading++;
    let bytes: Uint8Array;
    try {
      bytes = await file.bytes();
    } catch (err) {
      if ((err as { code?: string }).code === "ENOENT") return null;
      throw err;
    } finally {
      this.#reading--;
      this.#waiting.shift()?.();
    }
    return decodeBody(bytes, epoch);
  }

  remove(bodies: { id: string; epoch: number }[]): Promise<number> {
    if (bodies.length === 0) return Promise.resolve(0);
    const paths = bodies.flatMap((b) => {
      try {
        return [this.path(b.id, b.epoch)];
      } catch {
        return [];
      }
    });
    return this.#send({ op: "remove", paths });
  }

  close(): void {
    this.#fail("body store is closed");
    this.#worker.terminate();
  }

  #send(job: JobInput): Promise<number> {
    if (this.#broken) return Promise.reject(new BodyStoreError(this.#broken));
    const seq = ++this.#seq;
    const p = Promise.withResolvers<number>();
    this.#pending.set(seq, p);
    this.#worker.postMessage(
      { ...job, seq },
      job.op === "write" ? [job.head.buffer as ArrayBuffer, job.body.buffer as ArrayBuffer] : [],
    );
    return p.promise;
  }

  #fail(why: string): void {
    this.#broken ??= why;
    for (const p of this.#pending.values()) p.reject(new BodyStoreError(why));
    this.#pending.clear();
  }
}
