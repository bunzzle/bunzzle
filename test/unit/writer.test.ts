import { describe, expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";

function setup(maxBatch?: number) {
  const db = openDatabase({ path: ":memory:" });
  db.run("CREATE TABLE t (x INTEGER PRIMARY KEY)");
  const writer = new Writer(db, maxBatch === undefined ? {} : { maxBatch });
  const rows = () =>
    db
      .query<{ x: number }, []>("SELECT x FROM t ORDER BY x")
      .all()
      .map((r) => r.x);
  return { db, writer, rows };
}

describe("Writer", () => {
  test("commits operations from the same tick in one transaction", async () => {
    const { writer, rows } = setup();
    let commits = 0;
    writer.onCommit(() => commits++);
    const results = await Promise.all(
      [1, 2, 3].map((x) => writer.run((db) => db.run("INSERT INTO t VALUES (?)", [x]).changes)),
    );
    expect(results).toEqual([1, 1, 1]);
    expect(rows()).toEqual([1, 2, 3]);
    expect(commits).toBe(1);
  });

  test("operations from later ticks inside the wait share the commit", async () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("CREATE TABLE t (x INTEGER PRIMARY KEY)");
    const writer = new Writer(db, { maxWaitMs: 20 });
    let commits = 0;
    writer.onCommit(() => commits++);
    const first = writer.run((d) => d.run("INSERT INTO t VALUES (1)").changes);
    await new Promise((r) => setImmediate(r));
    const second = writer.run((d) => d.run("INSERT INTO t VALUES (2)").changes);
    expect(await Promise.all([first, second])).toEqual([1, 1]);
    expect(commits).toBe(1);
  });

  test("without a wait, the next tick commits", async () => {
    const db = openDatabase({ path: ":memory:" });
    db.run("CREATE TABLE t (x INTEGER PRIMARY KEY)");
    const writer = new Writer(db, { maxWaitMs: 0 });
    let commits = 0;
    writer.onCommit(() => commits++);
    await writer.run((d) => d.run("INSERT INTO t VALUES (1)").changes);
    await writer.run((d) => d.run("INSERT INTO t VALUES (2)").changes);
    expect(commits).toBe(2);
  });

  test("a failing operation rolls back alone", async () => {
    const { writer, rows } = setup();
    const a = writer.run((db) => db.run("INSERT INTO t VALUES (1)"));
    const b = writer.run((db) => {
      db.run("INSERT INTO t VALUES (2)");
      throw new Error("boom");
    });
    const c = writer.run((db) => db.run("INSERT INTO t VALUES (3)"));
    const [ra, rb, rc] = await Promise.allSettled([a, b, c]);
    expect(ra.status).toBe("fulfilled");
    expect(rb.status === "rejected" && (rb.reason as Error).message).toBe("boom");
    expect(rc.status).toBe("fulfilled");
    expect(rows()).toEqual([1, 3]);
  });

  test("when the whole batch is lost, the operation that broke it keeps its own error", async () => {
    const { writer, rows } = setup();
    const a = writer.run((db) => db.run("INSERT INTO t VALUES (1)"));
    const b = writer.run((db) => {
      db.run("ROLLBACK");
      throw new Error("broke the batch");
    });
    const [ra, rb] = await Promise.allSettled([a, b]);
    expect(ra.status).toBe("rejected");
    expect(rb.status === "rejected" && (rb.reason as Error).message).toBe("broke the batch");
    expect(rows()).toEqual([]);
  });

  test("splits work into batches of maxBatch", async () => {
    const { writer, rows } = setup(2);
    let commits = 0;
    writer.onCommit(() => commits++);
    await Promise.all(
      [1, 2, 3, 4, 5].map((x) => writer.run((db) => db.run("INSERT INTO t VALUES (?)", [x]))),
    );
    expect(rows()).toEqual([1, 2, 3, 4, 5]);
    expect(commits).toBe(3);
  });

  test("quiet batches do not notify listeners", async () => {
    const { writer } = setup();
    let commits = 0;
    writer.onCommit(() => commits++);
    await writer.run(() => 1, { quiet: true });
    expect(commits).toBe(0);
    await Promise.all([writer.run(() => 1, { quiet: true }), writer.run(() => 2)]);
    expect(commits).toBe(1);
  });

  test("close flushes pending work and rejects new work", async () => {
    const { writer, rows } = setup();
    const pending = writer.run((db) => db.run("INSERT INTO t VALUES (7)"));
    writer.close();
    await pending;
    expect(rows()).toEqual([7]);
    await expect(writer.run(() => 1)).rejects.toThrow("closed");
  });
});
