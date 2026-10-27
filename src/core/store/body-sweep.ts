import type { Database } from "bun:sqlite";
import type { BodyStore } from "./bodies.ts";

const CHUNK = 500;

async function names(dir: string, pattern: string, onlyFiles: boolean): Promise<string[]> {
  return Array.fromAsync(new Bun.Glob(pattern).scan({ cwd: dir, onlyFiles, dot: true })).catch(
    () => [] as string[],
  );
}

export async function sweepBodyFiles(
  db: Database,
  store: Pick<BodyStore, "root" | "remove" | "prune">,
  beforeEpoch: number,
): Promise<{ removed: number; dirs: number }> {
  const epochs = (await names(store.root, "*", false))
    .filter((n) => /^\d+$/.test(n))
    .map(Number)
    .filter((e) => e < beforeEpoch)
    .sort((a, b) => a - b);
  const kept = db.query<{ message_id: string }, [number, string]>(
    "SELECT message_id FROM body_files WHERE epoch = ? AND message_id IN (SELECT value FROM json_each(?))",
  );
  let removed = 0;
  let dirs = 0;
  for (const epoch of epochs) {
    const dir = `${store.root}/${epoch}`;
    const ids = (await names(dir, "*/*", true)).map((f) => f.slice(f.indexOf("/") + 1));
    for (let i = 0; i < ids.length; i += CHUNK) {
      const chunk = ids.slice(i, i + CHUNK);
      const live = new Set(kept.all(epoch, JSON.stringify(chunk)).map((r) => r.message_id));
      const gone = chunk.filter((id) => !live.has(id)).map((id) => ({ id, epoch }));
      removed += await store.remove(gone);
    }
    const shards = await names(dir, "*", false);
    dirs += await store.prune([...shards.map((s) => `${epoch}/${s}`), `${epoch}`]);
  }
  return { removed, dirs };
}
