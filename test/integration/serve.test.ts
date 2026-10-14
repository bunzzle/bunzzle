import { afterAll, beforeAll, describe, expect, test } from "bun:test";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const dataDir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-serve-${crypto.randomUUID()}`;

let proc: ReturnType<typeof Bun.spawn<"ignore", "pipe", "pipe">>;
let baseUrl: string;

async function firstLogLine(stream: ReadableStream<Uint8Array>): Promise<Record<string, unknown>> {
  const reader = stream.getReader();
  let buf = "";
  while (!buf.includes("\n")) {
    const { value, done } = await reader.read();
    if (done) throw new Error(`process exited before logging: ${buf}`);
    buf += new TextDecoder().decode(value);
  }
  reader.releaseLock();
  return JSON.parse(buf.slice(0, buf.indexOf("\n")));
}

beforeAll(async () => {
  proc = Bun.spawn(["bun", MAIN, "serve"], {
    env: { ...Bun.env, BUNZZLE_PORT: "0", BUNZZLE_DATA_DIR: dataDir },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const line = await firstLogLine(proc.stdout);
  expect(line["msg"]).toBe("listening");
  baseUrl = String(line["url"]).replace(/\/$/, "");
});

afterAll(async () => {
  if (proc.exitCode === null) proc.kill("SIGKILL");
  await Bun.$`rm -rf ${dataDir}`.quiet();
});

describe("bunzzle serve", () => {
  test("GET /health reports ok with version and db status", async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body["ok"]).toBe(true);
    expect(body["db"]).toBe("ok");
    expect(typeof body["version"]).toBe("string");
  });

  test("unknown routes return a JSON 404", async () => {
    const res = await fetch(`${baseUrl}/nope`);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: { code: "not_found", message: "Not found" } });
  });

  test("creates the database file in the data dir", async () => {
    expect(await Bun.file(`${dataDir}/bunzzle.db`).exists()).toBe(true);
  });

  test("SIGTERM shuts down cleanly with exit code 0", async () => {
    proc.kill("SIGTERM");
    expect(await proc.exited).toBe(0);
  });
});
