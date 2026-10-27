import type { Database } from "bun:sqlite";
import type { Logger } from "../log.ts";
import { type FreeSpace, freeMegabytes } from "../storage.ts";
import type { BodyStore } from "./bodies.ts";

interface Row {
  message_id: string;
  epoch: number;
  wrapped: Uint8Array;
  body: Uint8Array;
}

const MB = 1024 * 1024;

export async function moveBodiesToFiles(
  db: Database,
  store: Pick<BodyStore, "root" | "write">,
  log: Logger,
  {
    batch = 500,
    minFreeMb = 0,
    free = freeMegabytes,
  }: { batch?: number; minFreeMb?: number; free?: FreeSpace } = {},
): Promise<number> {
  const legacy = db
    .query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'bodies'")
    .get();
  if (!legacy) return 0;
  const left = db
    .query<{ n: number; bytes: number }, []>(
      "SELECT count(*) AS n, coalesce(sum(length(wrapped) + length(body)), 0) AS bytes FROM bodies",
    )
    .get() ?? { n: 0, bytes: 0 };
  if (left.n > 0) {
    const needMb = Math.ceil(left.bytes / MB) + minFreeMb;
    const freeMb = await free(store.root);
    if (freeMb !== null && freeMb < needMb) {
      throw new Error(
        `moving ${left.n} email bodies to ${store.root} needs ${needMb} MB free, ${freeMb} MB is free`,
      );
    }
    log.info("moving email bodies to files", { count: left.n, mb: Math.ceil(left.bytes / MB) });
  }

  const take = db.query<Row, [number]>(
    "SELECT message_id, epoch, wrapped, body FROM bodies ORDER BY message_id LIMIT ?",
  );
  const insert = db.query<unknown, [string, number, number]>(
    "INSERT INTO body_files (message_id, epoch, size) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
  );
  const drop = db.query<unknown, [string]>("DELETE FROM bodies WHERE message_id = ?");
  let moved = 0;
  for (;;) {
    const rows = take.all(batch);
    if (rows.length === 0) break;
    const sizes = await Promise.all(
      rows.map((r) =>
        store.write(
          r.message_id,
          { epoch: r.epoch, wrapped: new Uint8Array(r.wrapped), body: new Uint8Array(r.body) },
          { replace: true },
        ),
      ),
    );
    db.transaction(() => {
      for (const [i, r] of rows.entries()) {
        insert.run(r.message_id, r.epoch, sizes[i] as number);
        drop.run(r.message_id);
      }
    })();
    moved += rows.length;
    log.info("moved email bodies to files", { moved, of: left.n });
  }
  db.run("DROP TABLE bodies");
  return moved;
}
