import { expect, test } from "bun:test";
import { fuzz, report, shrink } from "./engine.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();

test("shrinking cuts a failing input down to the part that fails", async () => {
  const target = {
    seeds: [],
    run(input: Uint8Array) {
      if (dec.decode(input).includes("BAD")) throw new Error("found it");
    },
  };
  const small = await shrink(target, enc.encode(`${"x".repeat(5_000)}BAD${"y".repeat(3_000)}`));
  expect(dec.decode(small)).toBe("BAD");
});

test("expected errors are not findings and shrinking keeps the same kind of failure", async () => {
  const findings = await fuzz({
    seeds: [`${"a".repeat(200)}!${"b".repeat(200)}`],
    iterations: 0.01,
    expected: (e) => e instanceof RangeError,
    run(input) {
      const s = dec.decode(input);
      if (s.length < 10) throw new RangeError("short");
      if (s.includes("!")) throw new Error("bang");
    },
  });
  expect(findings.length).toBeGreaterThan(0);
  const f = findings[0];
  expect(f?.error).toBe("Error: bang");
  expect(dec.decode(Uint8Array.fromBase64(f?.input ?? "")).length).toBe(10);
  expect(report(findings)).toContain("shrunk from");
});
