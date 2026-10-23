import { afterEach, describe, expect, test } from "bun:test";
import { fromPem } from "../../src/asn1/der.ts";
import {
  type LinkTls,
  method,
  pinOf,
  RpcClient,
  type RpcError,
  type RpcServer,
  serveRpc,
} from "../../src/ipc/rpc.ts";
import { b } from "../../src/validate/schema.ts";
import { parseCertificate } from "../../src/x509/cert.ts";

const dir = `${import.meta.dir}/../fixtures/node`;
const read = (name: string) => Bun.file(`${dir}/${name}`).text();
const pin = async (name: string) =>
  pinOf(parseCertificate(fromPem(await read(name))[0] as Uint8Array).spki);

const ca = await read("ca.pem");
const node = { cert: await read("node.pem"), key: await read("node.key") };
const core = { cert: await read("core.pem"), key: await read("core.key") };
const corePin = await pin("core.pem");
const nodePin = await pin("node.pem");

const servers: RpcServer[] = [];
const clients: RpcClient[] = [];

afterEach(() => {
  for (const s of servers.splice(0)) s.stop();
  for (const c of clients.splice(0)) c.close();
});

const failure = (p: Promise<unknown>): Promise<RpcError> =>
  p.then(
    () => {
      throw new Error("expected the call to fail");
    },
    (e: RpcError) => e,
  );

let release: (() => void) | null = null;

async function start(pins = [corePin]) {
  const port = 20_000 + Math.floor(Math.random() * 20_000);
  const refused: string[] = [];
  servers.push(
    await serveRpc(
      { hostname: "127.0.0.1", port, tls: { ...node, ca, pins } },
      {
        add: method(b.object({ a: b.number(), b: b.number() }), ({ a, b }) => a + b),
        hang: method(
          b.object({}),
          () =>
            new Promise((resolve) => {
              release = () => resolve(null);
            }),
        ),
      },
      { onRefused: (reason) => refused.push(reason) },
    ),
  );
  return { port, refused };
}

function client(port: number, tls: Partial<LinkTls> = {}) {
  const c = new RpcClient({
    hostname: "127.0.0.1",
    port,
    tls: { ...core, ca, pins: [nodePin], name: "node-1", ...tls },
  });
  clients.push(c);
  return c;
}

async function refusedWith(certFile: string, keyFile: string, reason: RegExp) {
  const { port, refused } = await start();
  const c = client(port, { cert: await read(certFile), key: await read(keyFile) });
  const err = await failure(c.call("add", { a: 1, b: 2 }, { timeoutMs: 2000 }));
  expect(["lost", "unavailable"]).toContain(err.code);
  await Bun.sleep(20);
  expect(refused.join(" ")).toMatch(reason);
}

describe("rpc over TCP with mutual TLS", () => {
  test("pinned core and node talk", async () => {
    const { port, refused } = await start();
    const c = client(port);
    expect(await c.call("add", { a: 2, b: 3 })).toBe(5);
    expect(await c.call("add", { a: 4, b: 5 })).toBe(9);
    expect(c.path).toBe(`127.0.0.1:${port}`);
    expect(refused).toEqual([]);
  });

  test("certificate from another CA is refused", () =>
    refusedWith("core-other-ca.pem", "core.key", /refused/));

  test("expired certificate is refused", () =>
    refusedWith("core-expired.pem", "core.key", /refused|validity/));

  test("server certificate used as client is refused", () =>
    refusedWith("node.pem", "node.key", /refused|client use/));

  test("certificate for both purposes is refused", () =>
    refusedWith("core-both.pem", "core.key", /client use/));

  test("Ed25519 certificate is refused", async () => {
    const { port } = await start();
    const c = client(port, {
      cert: await read("core-ed25519.pem"),
      key: await read("core-ed25519.key"),
    });
    const err = await failure(c.call("add", { a: 1, b: 2 }, { timeoutMs: 2000 }));
    expect(["lost", "unavailable"]).toContain(err.code);
  });

  test("valid certificate with an unpinned key is refused", async () => {
    const { port, refused } = await start([nodePin]);
    const err = await failure(client(port).call("add", { a: 1, b: 2 }, { timeoutMs: 2000 }));
    expect(["lost", "unavailable"]).toContain(err.code);
    await Bun.sleep(20);
    expect(refused).toEqual(["peer key is not pinned"]);
  });

  test("core refuses a node whose key is not pinned", async () => {
    const { port } = await start();
    const err = await failure(client(port, { pins: [corePin] }).call("add", { a: 1, b: 2 }));
    expect(err.code).toBe("unavailable");
    expect(err.message).toContain("peer key is not pinned");
  });

  test("core refuses a node with the wrong name", async () => {
    const { port } = await start();
    const err = await failure(client(port, { name: "node-2" }).call("add", { a: 1, b: 2 }));
    expect(err.code).toBe("unavailable");
  });

  test("plain TCP gets no answer", async () => {
    const { port } = await start();
    const { promise, resolve } = Promise.withResolvers<string>();
    const socket = await Bun.connect({
      hostname: "127.0.0.1",
      port,
      socket: {
        open: (s) => {
          s.write('{"id":1,"method":"add","params":{"a":1,"b":2}}\n');
        },
        data: (_s, d) => {
          if (new TextDecoder().decode(d).includes('"result"')) resolve("answered");
        },
        close: () => resolve("closed"),
        error: () => resolve("closed"),
      },
    });
    setTimeout(() => resolve("silent"), 1000);
    expect(await promise).not.toBe("answered");
    socket.end();
  });

  test("TLS 1.2 is refused", async () => {
    const { port } = await start();
    const { promise, resolve } = Promise.withResolvers<boolean>();
    await Bun.connect({
      hostname: "127.0.0.1",
      port,
      tls: { ...core, ca, serverName: "node-1", secureOptions: 0x20000000 },
      socket: {
        handshake: (s, _ok, err) => {
          resolve(err === null && s.getTLSVersion() === "TLSv1.2");
          s.end();
        },
        data: () => {},
        close: () => resolve(false),
        error: () => resolve(false),
      },
    }).catch(() => resolve(false));
    expect(await promise).toBe(false);
  });

  test("calls in flight fail when the link drops", async () => {
    const { port } = await start();
    const c = client(port);
    expect(await c.call("add", { a: 1, b: 1 })).toBe(2);
    const pending = failure(c.call("hang", {}));
    await Bun.sleep(20);
    for (const s of servers.splice(0)) s.stop();
    const err = await pending;
    expect(err.code).toBe("lost");
    expect(err.message).toBe(`connection to 127.0.0.1:${port} lost`);
    release?.();
  });

  test("reconnects with backoff after a failed connect", async () => {
    const port = 40_000 + Math.floor(Math.random() * 10_000);
    const c = client(port);
    const first = await failure(c.call("add", { a: 1, b: 1 }));
    expect(first.code).toBe("unavailable");
    const second = await failure(c.call("add", { a: 1, b: 1 }));
    expect(second.message).toContain("waiting to reconnect");
    expect(second.retryAfter).toBe(1);
    servers.push(
      await serveRpc(
        { hostname: "127.0.0.1", port, tls: { ...node, ca, pins: [corePin] } },
        { add: method(b.object({ a: b.number(), b: b.number() }), ({ a, b }) => a + b) },
      ),
    );
    await Bun.sleep(300);
    expect(await c.call("add", { a: 1, b: 1 })).toBe(2);
  });
});
