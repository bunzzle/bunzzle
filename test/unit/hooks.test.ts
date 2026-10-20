import { describe, expect, test } from "bun:test";
import { parseCheckReply, parseScanReply } from "../../src/hooks/reply.ts";

describe("hook replies", () => {
  test("check: accept, refuse, change; 204 accepts", () => {
    expect(parseCheckReply(200, '{"action":"accept"}')).toEqual({ action: "accept" });
    expect(parseCheckReply(204, "")).toEqual({ action: "accept" });
    expect(parseCheckReply(200, '{"action":"refuse","reason":"no"}')).toEqual({
      action: "refuse",
      reason: "no",
    });
    expect(parseCheckReply(200, '{"action":"change","email":{"subject":"x","tags":[]}}')).toEqual({
      action: "change",
      email: { subject: "x", tags: [] },
    });
  });

  test("check: errors are strings, and only content fields can change", () => {
    expect(parseCheckReply(500, "")).toBe("answered 500");
    expect(parseCheckReply(200, "nope")).toBe("the reply is not JSON");
    expect(parseCheckReply(200, '{"action":"maybe"}')).toContain("accept, refuse or change");
    expect(parseCheckReply(200, '{"action":"change","email":{"to":"x@y.z","from":"a@b.c"}}')).toBe(
      "a hook cannot change to, from",
    );
  });

  test("scan: a numeric score", () => {
    expect(parseScanReply(200, '{"score":4.5,"action":"no action"}')).toBe(4.5);
    expect(parseScanReply(200, '{"score":"4"}')).toBe("the reply has no numeric `score`");
    expect(parseScanReply(503, "")).toBe("answered 503");
    expect(parseScanReply(200, "null")).toBe("the reply has no numeric `score`");
  });
});
