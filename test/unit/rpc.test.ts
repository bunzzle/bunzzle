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
      mirror: method(b.unknown(), (p) => p),
      bytes: method(b.object({ data: b.bytes() }), ({ data }) => ({ data, n: data.length })),
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

describe("progress", () => {
  test("progress frames arrive before the result, later ones are dropped", async () => {
    const path = `${dir}/${crypto.randomUUID()}.sock`;
    let late: (() => void) | null = null;
    servers.push(
      await serveRpc(path, {
        count: method(b.object({ n: b.number() }), ({ n }, ctx) => {
          for (let i = 1; i <= n; i++) ctx.progress({ i });
          late = () => ctx.progress({ i: 99 });
          return "done";
        }),
      }),
    );
    const client = new RpcClient(path);
    clients.push(client);
    const seen: number[] = [];
    const result = await client.call(
      "count",
      { n: 3 },
      {
        progress: b.object({ i: b.number() }),
        onProgress: (p) => seen.push(p.i),
      },
    );
    (late as unknown as () => void)();
    expect(await client.call("count", { n: 0 })).toBe("done");
    expect(result).toBe("done");
    expect(seen).toEqual([1, 2, 3]);
  });

  test("progress that fails its schema is skipped", async () => {
    const path = `${dir}/${crypto.randomUUID()}.sock`;
    servers.push(
      await serveRpc(path, {
        mixed: method(b.object({}), (_p, ctx) => {
          ctx.progress({ i: "x" });
          ctx.progress({ i: 2 });
          return null;
        }),
      }),
    );
    const client = new RpcClient(path);
    clients.push(client);
    const seen: number[] = [];
    await client.call(
      "mixed",
      {},
      {
        progress: b.object({ i: b.number() }),
        onProgress: (p) => seen.push(p.i),
      },
    );
    expect(seen).toEqual([2]);
  });

  test("progress is kept when the server process is killed before the result", async () => {
    const path = `${dir}/${crypto.randomUUID()}.sock`;
    const rpc = new URL("../../src/ipc/rpc.ts", import.meta.url).pathname;
    const schema = new URL("../../src/validate/schema.ts", import.meta.url).pathname;
    const proc = Bun.spawn(
      [
        process.execPath,
        "-e",
        `import { method, serveRpc } from ${JSON.stringify(rpc)};
         import { b } from ${JSON.stringify(schema)};
         await serveRpc(${JSON.stringify(path)}, {
           hang: method(b.object({}), (_p, ctx) => {
             ctx.progress({ i: 1 });
             return new Promise(() => {});
           }),
         });
         console.log("ready");`,
      ],
      { stdout: "pipe", stderr: "inherit" },
    );
    const reader = proc.stdout.getReader();
    await reader.read();
    const client = new RpcClient(path);
    clients.push(client);
    const seen: number[] = [];
    const call = client.call(
      "hang",
      {},
      {
        progress: b.object({ i: b.number() }),
        onProgress: (p) => {
          seen.push(p.i);
          proc.kill("SIGKILL");
        },
      },
    );
    const err = await failure(call);
    await proc.exited;
    expect(seen).toEqual([1]);
    expect(err.code).toBe("lost");
  });
});

describe("binary frames between local roles", () => {
  test("bytes and large strings arrive unchanged", async () => {
    const { client } = await start();
    const data = crypto.getRandomValues(new Uint8Array(300_000));
    const back = await client.call(
      "bytes",
      { data },
      { result: b.object({ data: b.bytes(), n: b.number() }) },
    );
    expect(back.n).toBe(data.length);
    expect(back.data).toEqual(data);
    const values = {
      mime: `Subject: x\r\n\r\n${'line "q" \\ \u00e7\u00ff\r\n'.repeat(2000)}`,
      lone: `a${"\ud800".repeat(5000)}`,
      small: "short",
      user: { "\u0000": 1, nested: ["\u0000", { "\u0000": "x" }] },
      list: [new Uint8Array([1, 2, 3]), "y".repeat(5000)],
    };
    const mirrored = (await client.call("mirror", values)) as typeof values;
    expect(mirrored.mime).toBe(values.mime);
    expect(mirrored.lone).toBe(values.lone);
    expect(mirrored.user).toEqual(values.user);
    expect(mirrored.small).toBe("short");
    expect(mirrored.list[1]).toBe("y".repeat(5000));
  });

  async function raw(path: string) {
    let text = "";
    let closed = false;
    const socket = await Bun.connect({
      unix: path,
      socket: {
        data: (_s, chunk) => {
          text += new TextDecoder("latin1").decode(chunk);
        },
        close: () => {
          closed = true;
        },
      },
    });
    const wait = async (done: () => boolean) => {
      for (let i = 0; i < 200 && !done(); i++) await Bun.sleep(5);
    };
    return { socket, wait, text: () => text, closed: () => closed };
  }

  function frame(head: unknown, sections: Uint8Array[]): Uint8Array {
    const json = new TextEncoder().encode(JSON.stringify(head));
    const size =
      11 + 4 * sections.length + json.length + sections.reduce((n, s) => n + s.length, 0);
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    view.setUint32(1, size - 5);
    view.setUint32(5, json.length);
    view.setUint16(9, sections.length);
    let at = 11;
    for (const s of sections) {
      view.setUint32(at, s.length);
      at += 4;
    }
    out.set(json, at);
    at += json.length;
    for (const s of sections) {
      out.set(s, at);
      at += s.length;
    }
    return out;
  }

  test("frames split into single bytes and mixed with JSON lines", async () => {
    const { path } = await start();
    const c = await raw(path);
    const bin = frame({ id: 1, method: "bytes", params: { data: { "\u0000": 0 } } }, [
      new Uint8Array(5000).fill(7),
    ]);
    const all = new Uint8Array([
      ...bin,
      ...new TextEncoder().encode(
        `${JSON.stringify({ id: 2, method: "add", params: { a: 1, b: 2 } })}\n`,
      ),
      ...bin,
    ]);
    for (const byte of all) {
      while (c.socket.write(new Uint8Array([byte])) === 0) await Bun.sleep(1);
    }
    await c.wait(() => c.text().split('"n":5000').length > 2 && c.text().includes('"result":3'));
    expect(c.text().split('"n":5000').length).toBe(3);
    expect(c.text()).toContain('"result":3');
    c.socket.end();
  });

  test("a frame whose sections do not add up closes the connection", async () => {
    const { path } = await start();
    const c = await raw(path);
    const bad = frame({ id: 1, method: "add", params: { a: 1, b: 2 } }, [new Uint8Array(10)]);
    new DataView(bad.buffer).setUint32(11, 9999);
    c.socket.write(bad);
    await c.wait(c.closed);
    expect(c.closed()).toBe(true);
  });
});
