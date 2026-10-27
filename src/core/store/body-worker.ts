import { Errno, type Libc, openLibc } from "./libc.ts";

declare const self: Worker;

export type BodyJob =
  | { seq: number; op: "probe"; root: string }
  | {
      seq: number;
      op: "write";
      dirs: string[];
      path: string;
      head: Uint8Array;
      body: Uint8Array;
      replace: boolean;
    }
  | { seq: number; op: "remove"; paths: string[] };

export type BodyReply =
  | { seq: number; ok: true; value: number }
  | { seq: number; ok: false; error: string; errno: number | null };

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;
const PROBE = new TextEncoder().encode("bunzzle body store probe\n");

let libc: Libc | null = null;
let broken: string | null = null;
const known = new Set<string>();
let queue: BodyJob[] = [];
let scheduled = false;

const parentOf = (path: string) => path.slice(0, path.lastIndexOf("/"));
const message = (err: unknown) => (err instanceof Error ? err.message : String(err));
const failed = (seq: number, err: unknown): BodyReply => ({
  seq,
  ok: false,
  error: message(err),
  errno: err instanceof Errno ? err.errno : null,
});

function c(): Libc {
  if (broken) throw new Error(broken);
  if (!libc) {
    try {
      libc = openLibc();
    } catch (err) {
      broken = `body store: libc is not available: ${message(err)}`;
      throw new Error(broken);
    }
  }
  return libc;
}

function ensureDir(l: Libc, dir: string, dirty: Set<string>): void {
  if (known.has(dir)) return;
  if (l.mkdir(dir, DIR_MODE)) dirty.add(parentOf(dir));
  known.add(dir);
}

function syncDir(l: Libc, dir: string): void {
  const fd = l.openRead(dir);
  try {
    l.sync(fd, dir);
  } finally {
    l.close(fd);
  }
}

function writeFile(l: Libc, path: string, parts: Uint8Array[], replace = true): void {
  const fd = replace ? l.create(path, FILE_MODE) : l.createNew(path, FILE_MODE);
  try {
    for (const p of parts) l.writeAll(fd, p, path);
    l.syncData(fd, path);
  } catch (err) {
    l.close(fd);
    try {
      l.unlink(path);
    } catch {}
    throw err;
  }
  l.close(fd);
}

function probe(l: Libc, root: string): number {
  const dirty = new Set<string>();
  known.delete(root);
  ensureDir(l, root, dirty);
  const path = `${root}/.probe`;
  writeFile(l, path, [PROBE]);
  syncDir(l, root);
  for (const d of dirty) syncDir(l, d);
  l.unlink(path);
  return PROBE.length;
}

function drain(): void {
  scheduled = false;
  const batch = queue;
  queue = [];
  const replies: BodyReply[] = [];
  const writes: { job: Extract<BodyJob, { op: "write" }>; size: number }[] = [];
  const dirty = new Set<string>();

  for (const job of batch) {
    try {
      const l = c();
      if (job.op === "probe") replies.push({ seq: job.seq, ok: true, value: probe(l, job.root) });
      else if (job.op === "remove") {
        let n = 0;
        for (const p of job.paths) if (l.unlink(p)) n++;
        replies.push({ seq: job.seq, ok: true, value: n });
      } else {
        for (const d of job.dirs) ensureDir(l, d, dirty);
        writeFile(l, job.path, [job.head, job.body], job.replace);
        dirty.add(parentOf(job.path));
        writes.push({ job, size: job.head.length + job.body.length });
      }
    } catch (err) {
      replies.push(failed(job.seq, err));
    }
  }

  const failedDirs = new Map<string, unknown>();
  for (const d of dirty) {
    try {
      syncDir(c(), d);
    } catch (err) {
      failedDirs.set(d, err);
      known.delete(d);
    }
  }
  for (const w of writes) {
    const hit = [...failedDirs].find(([d]) => w.job.path.startsWith(`${d}/`));
    if (hit) {
      try {
        c().unlink(w.job.path);
      } catch {}
    }
    replies.push(hit ? failed(w.job.seq, hit[1]) : { seq: w.job.seq, ok: true, value: w.size });
  }
  for (const r of replies) self.postMessage(r);
}

self.onmessage = (e: MessageEvent<BodyJob>) => {
  queue.push(e.data);
  if (!scheduled) {
    scheduled = true;
    setImmediate(drain);
  }
};
