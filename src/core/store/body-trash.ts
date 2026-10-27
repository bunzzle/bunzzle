import type { Database } from "bun:sqlite";
import type { BodyFiles } from "./bodies.ts";
import type { Writer } from "./writer.ts";

export async function emptyBodyTrash(
  db: Database,
  writer: Writer,
  store: Pick<BodyFiles, "remove">,
  limit = 1000,
): Promise<number> {
  const rows = db
    .query<{ message_id: string; epoch: number }, [number]>(
      "SELECT message_id, epoch FROM body_trash LIMIT ?",
    )
    .all(limit);
  if (rows.length === 0) return 0;
  await store.remove(rows.map((r) => ({ id: r.message_id, epoch: r.epoch })));
  await writer.run(
    (d) => {
      const done = d.query<unknown, [string, number]>(
        "DELETE FROM body_trash WHERE message_id = ? AND epoch = ?",
      );
      for (const r of rows) done.run(r.message_id, r.epoch);
    },
    { quiet: true },
  );
  return rows.length;
}
