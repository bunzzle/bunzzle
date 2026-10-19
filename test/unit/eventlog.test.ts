import { afterEach, describe, expect, test } from "bun:test";
import { appendEvent } from "../../src/core/events.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { beginAtEnd, exportEvents, nextBatch, setCursor } from "../../src/eventlog/export.ts";
import { EventLog } from "../../src/eventlog/log.ts";

const T0 = Date.UTC(2026, 9, 19, 10, 0, 0);
const DAY = 86_400_000;
const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs.splice(0)) await Bun.$`rm -rf ${d}`.quiet();
});

async function tempDir(): Promise<string> {
  const d = (await Bun.$`mktemp -d`.text()).trim();
  dirs.push(d);
  return d;
}

const files = (dir: string) => [...new Bun.Glob("*").scanSync({ cwd: dir })].sort();

async function linesOf(dir: string, name: string): Promise<string[]> {
  const bytes = await Bun.file(`${dir}/${name}`).bytes();
  const text = new TextDecoder().decode(name.endsWith(".gz") ? Bun.gunzipSync(bytes) : bytes);
  return text.split("\n").filter(Boolean);
}

describe("event log files", () => {
  test("lines go to a plain file named by its start time", async () => {
    const dir = await tempDir();
    const log = new EventLog({ dir, maxBytes: 1_000_000, keepDays: 30 });
    await log.start(T0);
    await log.write(['{"id":1}', '{"id":2}'], T0);
    await log.write(['{"id":3}'], T0 + 1000);
    expect(files(dir)).toEqual(["events-20261019-100000.jsonl"]);
    expect(await linesOf(dir, "events-20261019-100000.jsonl")).toEqual([
      '{"id":1}',
      '{"id":2}',
      '{"id":3}',
    ]);
  });

  test("a new UTC day or a full file starts a new segment; old ones are gzipped", async () => {
    const dir = await tempDir();
    const log = new EventLog({ dir, maxBytes: 20, keepDays: 30 });
    await log.start(T0);
    await log.write(['{"id":1}'], T0);
    await log.write(['{"id":2}'], T0 + 1000);
    await log.write(['{"id":3}'], T0 + 2000);
    await log.write(['{"id":4}'], T0 + DAY);
    await log.stop();
    expect(files(dir)).toEqual([
      "events-20261019-100000.jsonl.gz",
      "events-20261019-100002.jsonl.gz",
      "events-20261020-100000.jsonl.gz",
    ]);
    expect(await linesOf(dir, "events-20261019-100000.jsonl.gz")).toEqual(['{"id":1}', '{"id":2}']);
  });

  test("an idle log still closes yesterday's segment", async () => {
    const dir = await tempDir();
    const log = new EventLog({ dir, maxBytes: 1_000_000, keepDays: 30 });
    await log.start(T0);
    await log.write(['{"id":1}'], T0);
    await log.roll(T0 + 1000);
    expect(files(dir)).toEqual(["events-20261019-100000.jsonl"]);
    await log.roll(T0 + DAY);
    expect(files(dir)).toEqual(["events-20261019-100000.jsonl.gz"]);
  });

  test("after a crash the plain segment is compressed and never overwritten", async () => {
    const dir = await tempDir();
    const first = new EventLog({ dir, maxBytes: 1_000_000, keepDays: 30 });
    await first.start(T0);
    await first.write(['{"id":1}'], T0);
    const second = new EventLog({ dir, maxBytes: 1_000_000, keepDays: 30 });
    await second.start(T0);
    await second.write(['{"id":2}'], T0);
    expect(files(dir)).toEqual([
      "events-20261019-100000-1.jsonl",
      "events-20261019-100000.jsonl.gz",
    ]);
    expect(await linesOf(dir, "events-20261019-100000.jsonl.gz")).toEqual(['{"id":1}']);
  });

  test("segments older than the retention are deleted", async () => {
    const dir = await tempDir();
    const log = new EventLog({ dir, maxBytes: 1_000_000, keepDays: 2 });
    await log.start(T0);
    await log.write(['{"id":1}'], T0);
    await log.write(['{"id":2}'], T0 + DAY);
    await log.write(['{"id":3}'], T0 + 2 * DAY);
    await log.write(['{"id":4}'], T0 + 3 * DAY);
    expect(files(dir)).toEqual([
      "events-20261020-100000.jsonl.gz",
      "events-20261021-100000.jsonl.gz",
      "events-20261022-100000.jsonl",
    ]);
  });
});

describe("event export", () => {
  const db = () => {
    const d = openDatabase({ path: ":memory:" });
    d.run("INSERT INTO messages (id, type, payload, created_at) VALUES ('m', 'email', '{}', 0)");
    return d;
  };

  test("starts at the current end, then exports every new event once", () => {
    const d = db();
    appendEvent(d, { messageId: "m", kind: "queued", source: "api", at: T0 });
    beginAtEnd(d, T0);
    expect(nextBatch(d)).toBeNull();
    appendEvent(d, {
      messageId: "m",
      kind: "recipient",
      source: "delivery",
      at: T0 + 1000,
      data: { address: "a@b.test", status: "delivered" },
    });
    appendEvent(d, { messageId: "m", kind: "done", source: "core", at: T0 + 2000 });
    const batch = nextBatch(d);
    expect(batch?.lines.map((l) => JSON.parse(l))).toEqual([
      {
        id: 2,
        at: "2026-10-19T10:00:01.000Z",
        email_id: "m",
        event: "recipient",
        source: "delivery",
        data: { address: "a@b.test", status: "delivered" },
      },
      {
        id: 3,
        at: "2026-10-19T10:00:02.000Z",
        email_id: "m",
        event: "done",
        source: "core",
        data: {},
      },
    ]);
    setCursor(d, batch?.last ?? 0, T0);
    expect(nextBatch(d)).toBeNull();
    beginAtEnd(d, T0);
    appendEvent(d, { messageId: "m", kind: "late", source: "core", at: T0 + 3000 });
    expect(nextBatch(d)?.lines).toHaveLength(1);
  });

  test("a failed write keeps the events for later; nothing is lost or skipped", async () => {
    const d = db();
    beginAtEnd(d, T0);
    const dir = await tempDir();
    const file = new EventLog({ dir: `${dir}/gone`, maxBytes: 1_000_000, keepDays: 30 });
    const run = async <T>(fn: (x: typeof d) => T) => fn(d);
    appendEvent(d, { messageId: "m", kind: "queued", source: "api", at: T0 });
    await expect(exportEvents(run, file, () => T0)).rejects.toThrow();
    expect(nextBatch(d)?.lines).toHaveLength(1);

    await Bun.$`mkdir ${dir}/gone`.quiet();
    const ok = new EventLog({ dir: `${dir}/gone`, maxBytes: 1_000_000, keepDays: 30 });
    appendEvent(d, { messageId: "m", kind: "done", source: "core", at: T0 + 1 });
    await exportEvents(run, ok, () => T0);
    expect(nextBatch(d)).toBeNull();
    const [name] = files(`${dir}/gone`);
    expect((await linesOf(`${dir}/gone`, name as string)).map((l) => JSON.parse(l).event)).toEqual([
      "queued",
      "done",
    ]);
  });
});
