import { afterAll, beforeAll, describe, expect, test } from "bun:test";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;
const RUN = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-link-${crypto.randomUUID().slice(0, 8)}`;
const SOCK = `${RUN}/link.sock`;

let proc: ReturnType<typeof Bun.spawn>;
const echo = Bun.listen({
  hostname: "127.0.0.1",
  port: 0,
  socket: {
    data(s, chunk) {
      s.write(chunk);
    },
  },
});

function ask(header: string, then?: string): Promise<string> {
  const { promise, resolve } = Promise.withResolvers<string>();
  let got = "";
  void Bun.connect({
    unix: SOCK,
    socket: {
      open(s) {
        s.write(header);
      },
      data(s, chunk) {
        got += new TextDecoder().decode(chunk);
        if (then && got === '{"ok":true}\n') s.write(then);
        else if (!then || got.endsWith(then)) s.end();
      },
      close() {
        resolve(got);
      },
    },
  });
  return promise;
}

beforeAll(async () => {
  await Bun.$`mkdir -p ${RUN}`.quiet();
  proc = Bun.spawn(["bun", MAIN, "role", "link"], {
    env: { ...Bun.env, BUNZZLE_RUN_DIR: RUN },
    stdout: "ignore",
    stderr: "inherit",
  });
  const up = () =>
    Bun.file(SOCK)
      .stat()
      .then(() => true)
      .catch(() => false);
  for (let i = 0; i < 80 && !(await up()); i++) await Bun.sleep(50);
});

afterAll(async () => {
  proc.kill();
  echo.stop(true);
  await Bun.$`rm -rf ${RUN}`.quiet();
});

describe("link role", () => {
  test("pipes bytes to an IP and port", async () => {
    const got = await ask(`${JSON.stringify({ host: "127.0.0.1", port: echo.port })}\n`, "ping");
    expect(got).toBe('{"ok":true}\nping');
  });

  test("refuses a host name", async () => {
    const got = await ask(`${JSON.stringify({ host: "localhost", port: echo.port })}\n`);
    expect(JSON.parse(got).error.code).toBe("invalid");
  });

  test("refuses ports below 1024", async () => {
    const got = await ask(`${JSON.stringify({ host: "127.0.0.1", port: 25 })}\n`);
    expect(JSON.parse(got).error.code).toBe("invalid");
  });

  test("refuses a header without an end", async () => {
    const got = await ask("x".repeat(600));
    expect(JSON.parse(got).error.code).toBe("invalid");
  });
});
