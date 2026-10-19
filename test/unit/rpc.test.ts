import { afterEach, describe, expect, test } from "bun:test";
import { method, RpcClient, RpcError, type RpcServer, serveRpc } from "../../src/ipc/rpc.ts";
import { b } from "../../src/validate/schema.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-rpc-${crypto.randomUUID()}`;
await Bun.$`mkdir -p ${dir}`.quiet();
const servers: RpcServer[] = [];
const failure = (p: Promise<unknown>): Promise<RpcError> =>
  p.then(
    () => {
      throw new Error("expected the call to fail");
    },
    (e: RpcError) => e,
  );
const clients: RpcClient[] = [];

afterEach(() => {
  for (const s of servers.splice(0)) s.stop();
  for (const c of clients.splice(0)) c.close();
});

async function start(path = `${dir}/${crypto.randomUUID()}.sock`) {
  let slowRelease: (() => void) | null = null;
  servers.push(
    await serveRpc(path, {
      add: method(b.object({ a: b.number(), b: b.number() }), ({ a, b }) => a + b),
      echo: method(b.object({ text: b.string() }), ({ text }) => ({ text })),
      boom: method(b.object({}), () => {
        throw new RpcError("no-key", "no DKIM key for example.test");
      }),
      slow: method(
        b.object({}),
        () =>
          new Promise((resolve) => {
            slowRelease = () => resolve("late");
          }),
      ),
    }),
  );
  const client = new RpcClient(path);
  clients.push(client);
  return { path, client, release: () => slowRelease?.() };
}

describe("rpc over unix sockets", () => {
  test("calls methods and validates params on the server", async () => {
    const { client } = await start();
    expect(await client.call("add", { a: 2, b: 3 })).toBe(5);
    const bad = await failure(client.call("add", { a: "2" }));
    expect(bad).toBeInstanceOf(RpcError);
    expect(bad.code).toBe("invalid");
    expect((await failure(client.call("nope", {}))).code).toBe("invalid");
  });

  test("validates results on the client", async () => {
    const { client } = await start();
    const r = await failure(
      client.call("echo", { text: "x" }, { result: b.object({ text: b.number() }) }),
    );
    expect(r.code).toBe("invalid");
  });

  test("errors keep their code across the socket", async () => {
    const { client } = await start();
    const err = await failure(client.call("boom", {}));
    expect([err.code, err.message]).toEqual(["no-key", "no DKIM key for example.test"]);
  });

  test("many concurrent calls and a 20 MB payload", async () => {
    const { client } = await start();
    const sums = await Promise.all(
      Array.from({ length: 500 }, (_, i) => client.call("add", { a: i, b: 1 })),
    );
    expect(sums[499]).toBe(500);
    const text = "x".repeat(20 * 1024 * 1024);
    const back = await client.call<{ text: string }>("echo", { text });
    expect(back.text.length).toBe(text.length);
  });

  test("no server: unavailable, so the caller knows nothing was sent", async () => {
    const client = new RpcClient(`${dir}/missing.sock`);
    clients.push(client);
    expect((await failure(client.call("add", { a: 1, b: 1 }))).code).toBe("unavailable");
  });

  test("server gone mid-call: lost; the client reconnects when it is back", async () => {
    const { path, client } = await start();
    const pending = failure(client.call("slow", {}));
    await Bun.sleep(20);
    servers.pop()?.stop();
    expect((await pending).code).toBe("lost");
    await start(path);
    expect(await client.call("add", { a: 1, b: 2 })).toBe(3);
  });

  test("timeouts", async () => {
    const { client, release } = await start();
    const err = await failure(client.call("slow", {}, { timeoutMs: 50 }));
    expect(err.code).toBe("timeout");
    release();
  });

  test("the socket file is not world-accessible", async () => {
    const { path } = await start();
    expect((await Bun.file(path).stat()).mode & 0o007).toBe(0);
  });
});
