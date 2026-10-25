import { describe, expect, test } from "bun:test";
import { holdProgress } from "../../src/delivery/progress.ts";
import type { RecipientResult } from "../../src/smtp/session.ts";

const dot = (address: string): RecipientResult => ({
  address,
  status: "delivered",
  phase: "dot",
  code: 250,
  enhanced: "2.0.0",
  reply: "250 queued",
});

describe("held progress", () => {
  test("outcomes followed at once by the report are never sent", async () => {
    const sent: string[][] = [];
    const p = holdProgress((r) => sent.push(r.map((x) => x.address)), 20);
    p.onOutcomes([dot("a@example.test")]);
    p.drop();
    await Bun.sleep(40);
    expect(sent).toEqual([]);
  });

  test("outcomes of a long session are sent together after the hold", async () => {
    const sent: string[][] = [];
    const p = holdProgress((r) => sent.push(r.map((x) => x.address)), 20);
    p.onOutcomes([dot("a@example.test")]);
    p.onOutcomes([dot("b@example.test")]);
    await Bun.sleep(40);
    expect(sent).toEqual([["a@example.test", "b@example.test"]]);
    p.onOutcomes([dot("c@example.test")]);
    await Bun.sleep(40);
    expect(sent).toEqual([["a@example.test", "b@example.test"], ["c@example.test"]]);
  });

  test("a failed delivery sends what is held at once", () => {
    const sent: string[][] = [];
    const p = holdProgress((r) => sent.push(r.map((x) => x.address)), 60_000);
    p.onOutcomes([dot("a@example.test")]);
    p.flush();
    expect(sent).toEqual([["a@example.test"]]);
    p.flush();
    expect(sent).toHaveLength(1);
  });
});
