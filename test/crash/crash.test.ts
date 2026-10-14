import { expect, test } from "bun:test";
import { runCrash } from "./harness.ts";

test(
  "no message is lost or silently duplicated across SIGKILLs",
  async () => {
    const r = await runCrash({ messages: 20_000, kills: 5, minRunMs: 100, maxRunMs: 250 });
    expect(r.kills).toBe(5);
    expect(r).toMatchObject({
      done: 20_000,
      dead: 0,
      lost: 0,
      ackedMissingAfterKill: 0,
      unrecordedDuplicates: 0,
      unknownDeliveries: 0,
    });
  },
  { timeout: 120_000 },
);
