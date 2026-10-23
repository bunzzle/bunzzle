import { expect, test } from "bun:test";
import { onThisMachine } from "../../src/ips/local.ts";

test("an IP counts as on this machine only when a socket can bind it", async () => {
  expect(await onThisMachine("127.0.0.1")).toBe(true);
  expect(await onThisMachine("192.0.2.1")).toBe(false);
});
