import { afterAll, beforeAll, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
let served: Served;
let token: string;

beforeAll(async () => {
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_MIN_FREE_MB: "999999999",
  });
  const out = await Bun.$`bun ${MAIN} keys create --name t --scope full`
    .cwd(served.dir)
    .env({ PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" })
    .text();
  token = out.trim().split("\n").at(-1)?.trim() ?? "";
}, 30_000);

afterAll(async () => {
  await served.stop();
});

test("with too little free disk space, new email is refused with a temporary error", async () => {
  const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  const r = await fetch(`${served.url}/emails`, {
    method: "POST",
    headers,
    body: JSON.stringify({ from: "a@acme.test", to: ["b@example.test"], subject: "x", text: "x" }),
  });
  expect(r.status).toBe(503);
  expect(r.headers.get("retry-after")).toBe("60");
  const body = (await r.json()) as { name: string; message: string };
  expect(body.name).toBe("insufficient_storage");
  expect(body.message).toContain("below 999999999 MB");
  const metrics = await (await fetch(`${served.url}/metrics`, { headers })).text();
  expect(metrics).toContain("bunzzle_disk_low 1");
  expect(metrics).toMatch(/bunzzle_disk_free_bytes \d+/);
});
