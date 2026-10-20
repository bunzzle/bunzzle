import { afterAll, beforeAll, expect, test } from "bun:test";
import { generateMasterKey } from "../../src/crypto/master.ts";
import { type Served, startServe } from "../support/serve.ts";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const file = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-reload-${crypto.randomUUID()}.env`;
let served: Served;
let token: string;

beforeAll(async () => {
  await Bun.write(file, "BUNZZLE_MIN_FREE_MB=999999999\n");
  served = await startServe({
    BUNZZLE_MASTER_KEY: generateMasterKey(),
    BUNZZLE_MIN_FREE_MB: "999999999",
    BUNZZLE_ENV_FILE: file,
  });
  const out = await Bun.$`bun ${MAIN} keys create --name t --scope full`
    .cwd(served.dir)
    .env({ PATH: Bun.env["PATH"] ?? "", HOME: Bun.env["HOME"] ?? "" })
    .text();
  token = out.trim().split("\n").at(-1)?.trim() ?? "";
}, 30_000);

afterAll(async () => {
  await served.stop();
  await Bun.$`rm -f ${file}`.quiet();
});

const send = () =>
  fetch(`${served.url}/emails`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ from: "a@acme.test", to: ["b@example.test"], subject: "x", text: "x" }),
  });

test("SIGHUP to bunzzle serve reloads the env file in the running roles", async () => {
  expect((await send()).status).toBe(503);
  await Bun.write(file, "BUNZZLE_MIN_FREE_MB=0\n");
  served.proc.kill("SIGHUP");
  let status = 503;
  for (let i = 0; i < 50 && status === 503; i++) {
    await Bun.sleep(100);
    status = (await send()).status;
  }
  expect(status).toBe(403);
  expect(
    served.logs.some((l) => l["msg"] === "configuration reloaded" && l["role"] === "core"),
  ).toBe(true);
});
