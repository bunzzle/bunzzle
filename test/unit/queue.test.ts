import { describe, expect, test } from "bun:test";
import { openDatabase } from "../../src/core/store/db.ts";
import {
  activeSuspensions,
  expireSuspensions,
  resume,
  suspend,
  suspensionFor,
} from "../../src/queue/control.ts";

describe("suspensions", () => {
  test("by domain or provider, with an end time", () => {
    const db = openDatabase({ path: ":memory:" });
    suspend(db, "provider:google", "blocked us", 2_000, 1_000);
    suspend(db, "domain:slow.test", "asked us", null, 1_000);
    expect(suspensionFor(db, "gmail.com", "google", 1_500)?.reason).toBe("blocked us");
    expect(suspensionFor(db, "gmail.com", "microsoft", 1_500)).toBeNull();
    expect(suspensionFor(db, "slow.test", null, 1_500)?.reason).toBe("asked us");
    expect(suspensionFor(db, "gmail.com", "google", 2_000)).toBeNull();
    expireSuspensions(db, 2_000);
    expect(activeSuspensions(db, 2_000).map((s) => s.target)).toEqual(["domain:slow.test"]);
    suspend(db, "domain:slow.test", "still slow", 5_000, 1_600);
    expect(activeSuspensions(db, 1_600)[0]).toMatchObject({ reason: "still slow", until: 5_000 });
    expect(resume(db, "domain:slow.test", 1_700).resumed).toBe(true);
    expect(resume(db, "domain:slow.test", 1_700).resumed).toBe(false);
  });
});
