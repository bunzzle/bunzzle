import { afterAll, describe, expect, test } from "bun:test";
import { fromPem } from "../../src/asn1/der.ts";
import { nodesCommand } from "../../src/cli/nodes.ts";
import type { Config } from "../../src/config.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { type Methods, method, RpcClient, RpcError, serveRpc } from "../../src/ipc/rpc.ts";
import { CoreIdentity } from "../../src/nodes/identity.ts";
import { listNodes } from "../../src/nodes/registry.ts";
import { nodeChecks } from "../../src/roles/core-doctor.ts";
import { nodeMethods } from "../../src/roles/core-nodes.ts";
import { loadLinkTls } from "../../src/roles/node-link.ts";
import { NodeCa } from "../../src/signer/node-ca.ts";
import { b } from "../../src/validate/schema.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { parseCertificateRequest } from "../../src/x509/issue.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-nodes-${crypto.randomUUID()}`;
const socket = `/tmp/bunzzle-${crypto.randomUUID().slice(0, 8)}.sock`;
await Bun.$`mkdir -p ${dir}/keys`.quiet();
const master = await masterKeyFrom(generateMasterKey());
const ca = await NodeCa.open(`${dir}/keys/node-ca.json`, master, null, Date.now());
const signerServer = await serveRpc(socket, {
  issueNodeCertificate: method(
    b.object({ csr: b.string(), purpose: b.enum(["client", "server"]), days: b.number() }),
    async ({ csr, purpose, days }) => {
      const r = await parseCertificateRequest(Uint8Array.fromBase64(csr));
      return { cert: await ca.issue(r.name, r.spki, purpose, days, Date.now()), ca: ca.trusted() };
    },
  ),
});
const signer = new RpcClient(socket);
const quiet = createLogger("error");
const config = {} as Config;

afterAll(async () => {
  signer.close();
  signerServer.stop();
  await Bun.$`rm -rf ${dir} ${socket}`.quiet();
});

const invoke = (methods: Methods, name: string, params: unknown) => {
  const m = methods[name];
  if (!m) throw new Error(`no method ${name}`);
  return m.handle(m.params.parse(params));
};

async function core() {
  const db = openDatabase({ path: ":memory:" });
  const identity = await CoreIdentity.load(
    `${dir}/core-${crypto.randomUUID()}`,
    signer,
    Date.now(),
  );
  const methods = nodeMethods({ db, writer: new Writer(db), log: quiet, signer, identity });
  return { db, identity, methods };
}

async function requestCsr(nodeDir: string, name: string) {
  await nodesCommand(["request", name, "--dir", nodeDir], config);
  const text = await Bun.file(`${nodeDir}/request.csr`).text();
  return text.replace(/-----[A-Z ]+-----|\s+/g, "");
}

describe("delivery nodes", () => {
  test("request, add, install, then core and node talk over mutual TLS", async () => {
    const { db, identity, methods } = await core();
    const nodeDir = `${dir}/node-a`;
    const csr = await requestCsr(nodeDir, "node-a");
    expect((await Bun.$`stat -f %Lp ${nodeDir}/key.pem`.text()).trim()).toBe("600");

    const result = (await invoke(methods, "addNode", {
      name: "node-a",
      address: "127.0.0.1:7465",
      csr,
    })) as { corePins: string[] };
    expect(result.corePins).toEqual([identity.current().pin]);
    expect(listNodes(db).map((n) => n.name)).toEqual(["node-a"]);

    const bundle = `${dir}/node-a.bundle.json`;
    await Bun.write(bundle, JSON.stringify(result));
    await nodesCommand(["install", bundle, "--dir", nodeDir], config);
    const tls = await loadLinkTls(nodeDir);
    expect(tls.pins).toEqual([identity.current().pin]);

    const port = 20_000 + Math.floor(Math.random() * 20_000);
    const server = await serveRpc(
      { hostname: "127.0.0.1", port, tls },
      { ping: method(b.object({}), () => "pong") },
    );
    const me = identity.current();
    const client = new RpcClient({
      hostname: "127.0.0.1",
      port,
      tls: {
        cert: me.cert,
        key: me.key,
        ca: me.ca,
        pins: [listNodes(db)[0]?.pin ?? ""],
        name: "node-a",
      },
    });
    try {
      expect(await client.call("ping", {})).toBe("pong");
    } finally {
      client.close();
      server.stop();
    }
  });

  test("core identity is a 7-day client certificate kept across restarts", async () => {
    const at = `${dir}/core-keep`;
    const first = await CoreIdentity.load(at, signer, Date.now());
    const again = await CoreIdentity.load(at, signer, Date.now());
    expect(again.current().pin).toBe(first.current().pin);
    expect(first.current().notAfter - Date.now()).toBeGreaterThan(6.9 * 86_400_000);
    expect((await Bun.$`stat -f %Lp ${at}/core.json`.text()).trim()).toBe("600");
    const expired = await CoreIdentity.load(at, signer, Date.now() + 8 * 86_400_000);
    expect(expired.current().pin).not.toBe(first.current().pin);
  });

  test("renew hands over the next identity before switching", async () => {
    const { identity } = await core();
    const before = identity.current().pin;
    let seen = "";
    const next = await identity.renew(async (n) => {
      seen = n.pin;
      expect(identity.current().pin).toBe(before);
    });
    expect(seen).toBe(next.pin);
    expect(identity.current().pin).toBe(next.pin);
    expect(next.pin).not.toBe(before);
  });

  test("bad names, bad addresses, wrong CSR name and duplicates are refused", async () => {
    const { methods } = await core();
    const csr = await requestCsr(`${dir}/node-b`, "node-b");
    const refused = async (params: unknown) => {
      try {
        await invoke(methods, "addNode", params);
      } catch (err) {
        return (err as RpcError).message;
      }
      throw new Error("expected a refusal");
    };
    expect(await refused({ name: "Node_B", address: "127.0.0.1:7465", csr })).toMatch(/names/);
    expect(await refused({ name: "node-b", address: "host:7465", csr })).toMatch(/<ip>:<port>/);
    expect(await refused({ name: "node-b", address: "127.0.0.1:80", csr })).toMatch(/1024/);
    expect(await refused({ name: "node-c", address: "127.0.0.1:7465", csr })).toMatch(
      /for node-b, not node-c/,
    );
    await invoke(methods, "addNode", { name: "node-b", address: "127.0.0.1:7465", csr });
    expect(await refused({ name: "node-b", address: "127.0.0.1:7466", csr })).toMatch(/already/);
  });

  test("install refuses a bundle made for another key", async () => {
    const { methods } = await core();
    const csr = await requestCsr(`${dir}/node-d`, "node-d");
    const result = await invoke(methods, "addNode", {
      name: "node-d",
      address: "127.0.0.1:7467",
      csr,
    });
    const bundle = `${dir}/node-d.bundle.json`;
    await Bun.write(bundle, JSON.stringify(result));
    await nodesCommand(["request", "node-d", "--dir", `${dir}/node-d`, "--force"], config);
    await expect(
      nodesCommand(["install", bundle, "--dir", `${dir}/node-d`], config),
    ).rejects.toThrow(/not issued for the key/);
    expect(await Bun.file(`${dir}/node-d/cert.pem`).exists()).toBe(false);
  });

  test("remove drops the node", async () => {
    const { db, methods } = await core();
    const csr = await requestCsr(`${dir}/node-e`, "node-e");
    await invoke(methods, "addNode", { name: "node-e", address: "127.0.0.1:7468", csr });
    expect(await invoke(methods, "removeNode", { name: "node-e" })).toEqual({
      name: "node-e",
      removed: true,
    });
    expect(listNodes(db)).toEqual([]);
    await expect(
      Promise.resolve().then(() => invoke(methods, "removeNode", { name: "node-e" })),
    ).rejects.toBeInstanceOf(RpcError);
  });

  test("doctor warns 60 days before CA expiry and 3 days before a node certificate expires", () => {
    const DAY = 86_400_000;
    const caEnd = parseCertificate(fromPem(ca.trusted())[0] as Uint8Array).notAfter;
    const node = (name: string, notAfter: number) => ({
      name,
      address: "127.0.0.1:7465",
      pin: "sha256/x",
      notAfter,
      createdAt: 0,
    });
    expect(nodeChecks([], ca.trusted(), Date.now())).toEqual([]);
    const at = caEnd - 61 * DAY;
    const fresh = nodeChecks(
      [node("a", at + 10 * DAY), node("b", at + 2 * DAY), node("c", at - DAY)],
      ca.trusted(),
      at,
    );
    expect(fresh.map((c) => [c.item.replace(/-[0-9a-f]{8}$/, ""), c.status])).toEqual([
      ["CA bunzzle-node-ca", "ok"],
      ["a certificate", "ok"],
      ["b certificate", "warn"],
      ["c certificate", "fail"],
    ]);
    expect(fresh[2]?.detail).toMatch(/in 2 days$/);
    expect(fresh[3]?.detail).toMatch(/^expired /);
    const late = nodeChecks([node("a", caEnd)], ca.trusted(), caEnd - 59 * DAY);
    expect(late[0]?.status).toBe("warn");
  });
});
