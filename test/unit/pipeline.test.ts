import { describe, expect, test } from "bun:test";
import { defer, fail, ok } from "../../src/core/outcome.ts";
import { runPhase, type Stage } from "../../src/core/pipeline.ts";

const stage = (name: string, run: Stage<string[]>["run"]): Stage<string[]> => ({ name, run });
const visit = (name: string) =>
  stage(name, (seen) => {
    seen.push(name);
    return ok.continue;
  });

describe("runPhase", () => {
  test("all stages continuing is done", async () => {
    const seen: string[] = [];
    expect(await runPhase([visit("a"), visit("b")], seen)).toEqual({
      outcome: { kind: "done" },
      stage: undefined,
    });
    expect(seen).toEqual(["a", "b"]);
  });

  test("stops at the first stage that does not continue", async () => {
    const seen: string[] = [];
    const result = await runPhase(
      [visit("a"), stage("b", () => fail("bad", "nope")), visit("c")],
      seen,
    );
    expect(result).toEqual({ outcome: { kind: "fail", code: "bad", reason: "nope" }, stage: "b" });
    expect(seen).toEqual(["a"]);
  });

  test("done ends the phase early", async () => {
    const seen: string[] = [];
    const result = await runPhase([stage("a", () => ok.done), visit("b")], seen);
    expect(result.outcome.kind).toBe("done");
    expect(seen).toEqual([]);
  });

  test("async stages and defer", async () => {
    const result = await runPhase([stage("a", async () => defer("later", 50))], []);
    expect(result.outcome).toEqual({ kind: "defer", reason: "later", delayMs: 50 });
  });

  test("a throwing stage is unknown", async () => {
    const result = await runPhase(
      [
        stage("a", () => {
          throw new Error("socket reset");
        }),
      ],
      [],
    );
    expect(result).toEqual({
      outcome: { kind: "unknown", reason: "stage threw: socket reset" },
      stage: "a",
    });
  });
});
