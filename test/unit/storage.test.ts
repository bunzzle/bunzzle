import { describe, expect, test } from "bun:test";
import { createLogger } from "../../src/core/log.ts";
import { freeMegabytes, StorageWatch } from "../../src/core/storage.ts";

function watch(min: number, values: (number | null)[]) {
  const lines: Record<string, unknown>[] = [];
  const log = createLogger("debug", {}, (l) => lines.push(JSON.parse(l)));
  let i = 0;
  const w = new StorageWatch(
    "/data",
    () => min,
    log,
    async () => values[i++] ?? null,
  );
  return { w, lines, msgs: () => lines.map((l) => String(l["msg"])) };
}

describe("storage watch", () => {
  test("low below the limit, logged once when it goes low and once when it recovers", async () => {
    const { w, msgs } = watch(1024, [5000, 900, 800, 2000]);
    expect((await w.check()).low).toBe(false);
    expect((await w.check()).low).toBe(true);
    expect(w.low()).toBe(true);
    expect(await w.check()).toEqual({ freeMb: 800, minFreeMb: 1024, low: true });
    expect((await w.check()).low).toBe(false);
    expect(msgs()).toEqual([
      "free disk space is low: new email is refused until space is freed",
      "free disk space is back above the limit: new email is accepted",
    ]);
  });

  test("an unreadable free space never blocks email and is reported once", async () => {
    const { w, msgs } = watch(1024, [900, null, null]);
    expect((await w.check()).low).toBe(true);
    expect((await w.check()).low).toBe(false);
    await w.check();
    expect(msgs().filter((m) => m.startsWith("cannot read"))).toHaveLength(1);
  });

  test("a limit of 0 turns the check off", async () => {
    const { w } = watch(0, [1]);
    expect(await w.check()).toEqual({ freeMb: null, minFreeMb: 0, low: false });
  });

  test("df reads the real free space; a missing directory gives null", async () => {
    expect(await freeMegabytes(import.meta.dir)).toBeGreaterThan(0);
    expect(await freeMegabytes(`/no/such/dir/${crypto.randomUUID()}`)).toBeNull();
  });
});
