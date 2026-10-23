import { describe, expect, test } from "bun:test";
import { method, RpcClient, RpcError, serveRpc } from "../../src/ipc/rpc.ts";
import {
  API_METHODS,
  API_PUBLIC_METHODS,
  apiMethods,
  INBOUND_METHODS,
  inboundMethods,
} from "../../src/roles/core-access.ts";
import { b } from "../../src/validate/schema.ts";

const SRC = `${import.meta.dir}/../../src`;

async function calledIn(paths: string[]): Promise<Set<string>> {
  const out = new Set<string>();
  for (const pattern of paths) {
    for await (const f of new Bun.Glob(pattern).scan({ cwd: SRC })) {
      const t = await Bun.file(`${SRC}/${f}`).text();
      for (const m of t.matchAll(/\b(?:rpc|call)(?:<[^(]*?>)?\(\s*"([a-zA-Z]+)"/g)) {
        out.add(m[1] as string);
      }
    }
  }
  return out;
}

const OPERATOR_ONLY = ["createKey", "listKeys", "revokeKey", "addHook", "listHooks", "removeHook"];

describe("core sockets", () => {
  test("the api socket has every method the api role calls, and no operator methods", async () => {
    const called = await calledIn([
      "http/*.ts",
      "roles/api.ts",
      "roles/runtime.ts",
      "submission/*.ts",
      "tracking/*.ts",
    ]);
    const served = new Set([...API_METHODS, ...API_PUBLIC_METHODS]);
    expect([...called].filter((m) => !served.has(m))).toEqual([]);
    expect(OPERATOR_ONLY.filter((m) => served.has(m))).toEqual([]);
  });

  test("the inbound socket has exactly what the inbound role calls", async () => {
    const called = await calledIn(["roles/inbound.ts", "roles/runtime.ts", "inbound/*.ts"]);
    expect([...called].sort()).toEqual([...INBOUND_METHODS].sort());
  });

  test("api methods need a key; public ones do not", async () => {
    const all = Object.fromEntries(
      [...API_METHODS, ...API_PUBLIC_METHODS, ...INBOUND_METHODS, ...OPERATOR_ONLY].map((n) => [
        n,
        method(b.object({ tokenHash: b.string().optional() }), () => n),
      ]),
    );
    const api = apiMethods(all);
    expect(() => api["listEmails"]?.handle({})).toThrow(
      new RpcError("unauthenticated", "API key is required"),
    );
    expect(api["listEmails"]?.handle({ tokenHash: "h" })).toBe("listEmails");
    expect(api["health"]?.handle({})).toBe("health");
    expect(api["createKey"]).toBeUndefined();
    expect(Object.keys(inboundMethods(all)).sort()).toEqual([...INBOUND_METHODS].sort());
  });

  test("the admin socket is open only to its owner", async () => {
    const dir = await Bun.$`mktemp -d`.text();
    const path = `${dir.trim()}/admin.sock`;
    const server = await serveRpc(
      path,
      { ping: method(b.object({}), () => "pong") },
      { mode: "600" },
    );
    try {
      expect((await Bun.file(path).stat()).mode & 0o777).toBe(0o600);
      const client = new RpcClient(path);
      expect(await client.call("ping", {})).toBe("pong");
      client.close();
    } finally {
      server.stop();
    }
  });
});
