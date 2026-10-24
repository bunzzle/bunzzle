import { afterAll, describe, expect, test } from "bun:test";
import { fromPem } from "../../src/asn1/der.ts";
import { nodesCommand } from "../../src/cli/nodes.ts";
import { type Config, ConfigError } from "../../src/config.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { Writer } from "../../src/core/store/writer.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { egressVia } from "../../src/egress/tunnel.ts";
import {
  type Methods,
  method,
  RpcClient,
  RpcError,
  type RpcServer,
  serveRpc,
} from "../../src/ipc/rpc.ts";
import { DeliveryIdentity } from "../../src/nodes/delivery-identity.ts";
import { DeliveryLinkKeeper } from "../../src/nodes/delivery-link.ts";
import { DeliveryFleet, LOCAL } from "../../src/nodes/fleet.ts";
import { CoreIdentity } from "../../src/nodes/identity.ts";
import { NodeLinks } from "../../src/nodes/links.ts";
import { nodeLinkMethods } from "../../src/nodes/node.ts";
import { listNodes } from "../../src/nodes/registry.ts";
import { fleetChecks, nodeChecks } from "../../src/roles/core-doctor.ts";
import { nodeMethods } from "../../src/roles/core-nodes.ts";
import { runEgress } from "../../src/roles/egress.ts";
import { loadLinkTls } from "../../src/roles/node-link.ts";
import { NodeCa } from "../../src/signer/node-ca.ts";
import { SessionPool } from "../../src/smtp/pool.ts";
import { runSession, type SessionInput } from "../../src/smtp/session.ts";
import { b } from "../../src/validate/schema.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { parseCertificateRequest } from "../../src/x509/issue.ts";
import { type FakeMx, type MxScenario, startFakeMx, TEST_CA } from "../support/fake-mx.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-nodes-${crypto.randomUUID()}`;
await Bun.$`mkdir -p ${dir}/keys`.quiet();
const master = await masterKeyFrom(generateMasterKey());
const quiet = createLogger("error");
const config = {} as Config;
const cleanup: (() => void)[] = [];

async function startSigner(ca: NodeCa) {
  const socket = `/tmp/bunzzle-${crypto.randomUUID().slice(0, 8)}.sock`;
  const server = await serveRpc(socket, {
    issueNodeCertificate: method(
      b.object({ csr: b.string(), purpose: b.enum(["client", "server"]), days: b.number() }),
      async ({ csr, purpose, days }) => {
        const r = await parseCertificateRequest(Uint8Array.fromBase64(csr));
        return {
          cert: await ca.issue(r.name, r.spki, purpose, days, Date.now()),
          ca: ca.trusted(),
        };
      },
    ),
    nodeCa: method(b.object({}), () => ca.trusted()),
    nodeCaStates: method(b.object({}), () => ca.states()),
    rotateNodeCa: method(b.object({ step: b.string() }), async ({ step }) => {
      if (step === "start") await ca.rotateStart(Date.now());
      else if (step === "promote") await ca.promote();
      else return { cas: ca.states(), dropped: await ca.dropRetiring() };
      return { cas: ca.states(), dropped: [] };
    }),
  });
  const client = new RpcClient(socket);
  cleanup.push(() => {
    client.close();
    server.stop();
    Bun.$`rm -f ${socket}`.quiet();
  });
  return client;
}

const ca = await NodeCa.open(`${dir}/keys/node-ca.json`, master, null, Date.now());
const signer = await startSigner(ca);

afterAll(async () => {
  for (const c of cleanup) c();
  await Bun.$`rm -rf ${dir}`.quiet();
});

const invoke = (methods: Methods, name: string, params: unknown) => {
  const m = methods[name];
  if (!m) throw new Error(`no method ${name}`);
  return m.handle(m.params.parse(params));
};

async function core(client = signer, clock = { now: Date.now() }) {
  const db = openDatabase({ path: ":memory:" });
  const writer = new Writer(db);
  const identity = await CoreIdentity.load(
    `${dir}/core-${crypto.randomUUID()}`,
    client,
    Date.now(),
  );
  const now = () => clock.now;
  const deliveryIdentity = new DeliveryIdentity();
  const socket = `/tmp/bunzzle-${crypto.randomUUID().slice(0, 8)}.sock`;
  const deliveryServer = await serveRpc(socket, deliveryIdentity.methods());
  const delivery = new RpcClient(socket);
  cleanup.push(() => {
    delivery.close();
    deliveryServer.stop();
  });
  let keeper: DeliveryLinkKeeper | null = null;
  const links = new NodeLinks({
    db,
    writer,
    log: quiet,
    signer: client,
    identity,
    now,
    deliveryPins: () => keeper?.pins() ?? null,
  });
  cleanup.push(() => links.closeAll());
  keeper = new DeliveryLinkKeeper({ delivery, signer: client, links, log: quiet, now });
  const deliveryLink = keeper;
  const methods = nodeMethods({
    db,
    writer,
    log: quiet,
    signer: client,
    identity,
    links,
    now,
    deliveryLink,
  });
  return { db, identity, methods, links, deliveryIdentity, deliveryLink, clock };
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
    expect((await Bun.file(`${nodeDir}/key.pem`).stat()).mode & 0o777).toBe(0o600);

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
    expect((await Bun.file(`${at}/core.json`).stat()).mode & 0o777).toBe(0o600);
    const expired = await CoreIdentity.load(at, signer, Date.now() + 8 * 86_400_000);
    expect(expired.current().pin).toBe(first.current().pin);
    expect(expired.current().cert).not.toBe(first.current().cert);
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
      kind: "delivery" as const,
      address: "127.0.0.1:7465",
      pin: "sha256/x",
      notAfter,
      ca: "",
      trustedCas: [],
      corePins: [],
      createdAt: 0,
    });
    expect(nodeChecks([], ca.trusted(), "sha256/core", Date.now())).toEqual([]);
    const at = caEnd - 61 * DAY;
    const fresh = nodeChecks(
      [node("a", at + 10 * DAY), node("b", at + 2 * DAY), node("c", at - DAY)],
      ca.trusted(),
      "sha256/core",
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
    const late = nodeChecks([node("a", caEnd)], ca.trusted(), "sha256/core", caEnd - 59 * DAY);
    expect(late[0]?.status).toBe("warn");
  });

  test("CA rotation: start, promote once nodes trust the new CA, finish once they hold its certificates", async () => {
    await Bun.$`mkdir -p ${dir}/rot`.quiet();
    const rotCa = await NodeCa.open(`${dir}/rot/node-ca.json`, master, null, Date.now());
    const client = await startSigner(rotCa);
    const { db, identity, methods } = await core(client);
    const csr = await requestCsr(`${dir}/node-r`, "node-r");
    await invoke(methods, "addNode", { name: "node-r", address: "127.0.0.1:7470", csr });
    const [first] = rotCa.states();
    const pin = identity.current().pin;
    const step = (s: string) => invoke(methods, "rotateNodeCa", { step: s });
    const refusal = (s: string) =>
      Promise.resolve()
        .then(() => step(s))
        .then(
          () => {
            throw new Error("expected a refusal");
          },
          (e: RpcError) => e.message,
        );
    const issuerOf = () =>
      fromPem(identity.current().ca)
        .map((d) => parseCertificate(d))
        .find((c) => {
          const cert = parseCertificate(fromPem(identity.current().cert)[0] as Uint8Array);
          return (
            c.subject.every((x, i) => x === cert.issuer[i]) &&
            c.subject.length === cert.issuer.length
          );
        })?.commonNames[0];

    expect(listNodes(db)[0]?.trustedCas).toEqual([first?.name ?? ""]);
    expect(await invoke(methods, "nodeCaRotation", {})).toMatchObject({ pending: null });
    expect(await refusal("promote")).toMatch(/no CA rotation in progress/);

    const started = (await step("start")) as { pending: { step: string; nodes: string[] } };
    expect(started.pending).toEqual({ step: "promote", nodes: ["node-r"] });
    const next = rotCa.states()[1]?.name ?? "";
    expect(fromPem(identity.current().ca)).toHaveLength(2);
    expect(issuerOf()).toBe(first?.name);
    expect(identity.current().pin).toBe(pin);
    expect(await refusal("start")).toMatch(/in progress: next step is promote/);
    expect(await refusal("finish")).toMatch(/next step is promote/);
    expect(await refusal("promote")).toMatch(/node-r do not trust the new CA yet/);

    db.run("UPDATE nodes SET trusted_cas = ? WHERE name = 'node-r'", [
      JSON.stringify([first?.name, next]),
    ]);
    const promoted = (await step("promote")) as { pending: { step: string; nodes: string[] } };
    expect(promoted.pending).toEqual({ step: "finish", nodes: ["node-r"] });
    expect(issuerOf()).toBe(next);
    expect(identity.current().pin).toBe(pin);
    expect(await refusal("finish")).toMatch(/node-r still have a certificate from the old CA/);

    db.run("UPDATE nodes SET ca = ? WHERE name = 'node-r'", [next]);
    const finished = (await step("finish")) as {
      cas: { name: string }[];
      pending: null;
      dropped: unknown;
    };
    expect(finished.cas.map((c) => c.name)).toEqual([next]);
    expect(finished.pending).toBeNull();
    expect(finished.dropped).toEqual([{ name: first?.name ?? "", store_key: null }]);
    expect(fromPem(identity.current().ca)).toHaveLength(1);
    expect(identity.current().pin).toBe(pin);
  });

  test("core picks up a CA change made while it was down", async () => {
    await Bun.$`mkdir -p ${dir}/heal`.quiet();
    const healCa = await NodeCa.open(`${dir}/heal/node-ca.json`, master, null, Date.now());
    const client = await startSigner(healCa);
    const at = `${dir}/core-heal`;
    const before = await CoreIdentity.load(at, client, Date.now());
    await healCa.rotateStart(Date.now());
    const after = await CoreIdentity.load(at, client, Date.now());
    expect(after.current().ca).toBe(healCa.trusted());
    expect(after.current().pin).toBe(before.current().pin);
  });
});

let nextPort = 21_000 + Math.floor(Math.random() * 15_000);

async function startNode(c: Awaited<ReturnType<typeof core>>, name: string, ips: string[] = []) {
  const nodeDir = `${dir}/${name}-${crypto.randomUUID().slice(0, 6)}`;
  const port = nextPort++;
  const csr = await requestCsr(nodeDir, name);
  const bundle = await invoke(c.methods, "addNode", { name, address: `127.0.0.1:${port}`, csr });
  await Bun.write(`${nodeDir}/bundle.json`, JSON.stringify(bundle));
  await nodesCommand(["install", `${nodeDir}/bundle.json`, "--dir", nodeDir], config);
  const tls = await loadLinkTls(nodeDir);
  let release: (() => void) | null = null;
  const serve = async (): Promise<RpcServer> => {
    const s: RpcServer = await serveRpc(
      { hostname: "127.0.0.1", port, tls },
      {
        ping: method(b.object({}), () => "pong"),
        ips: method(b.object({}), () => ips.map((ip) => ({ ip }))),
        hang: method(
          b.object({}),
          () =>
            new Promise((resolve) => {
              release = () => resolve(null);
            }),
        ),
        ...nodeLinkMethods(nodeDir, tls, () => node.server),
      },
    );
    return s;
  };
  const node = {
    nodeDir,
    tls,
    ips,
    server: null as unknown as RpcServer,
    restart: async () => {
      node.server = await serve();
    },
  };
  node.server = await serve();
  cleanup.push(() => {
    release?.();
    node.server.stop();
  });
  return node;
}

const pinsOn = async (nodeDir: string) =>
  (await Bun.file(`${nodeDir}/peer.pin`).text()).trim().split("\n");
const ping = (c: Awaited<ReturnType<typeof core>>, name: string) =>
  c.links.client(name)?.call("ping", {}, { timeoutMs: 5_000 });

describe("node links", () => {
  test("a healthy node needs no changes and its state is saved", async () => {
    const c = await core();
    const node = await startNode(c, "link-a");
    const st = await c.links.reconcile("link-a");
    expect(st.corePins).toEqual([c.identity.current().pin]);
    expect(st.issuer).toBe(ca.states()[0]?.name ?? "");
    expect(await ping(c, "link-a")).toBe("pong");
    expect(await pinsOn(node.nodeDir)).toEqual([c.identity.current().pin]);
    expect(listNodes(c.db)[0]?.trustedCas).toEqual(st.cas);
  });

  test("a node certificate with less than 10 days left is renewed with a key made on the node", async () => {
    const clock = { now: Date.now() };
    const c = await core(signer, clock);
    const node = await startNode(c, "link-b");
    const before = listNodes(c.db)[0];
    const keyBefore = await Bun.file(`${node.nodeDir}/key.pem`).text();
    clock.now += 21 * 86_400_000;
    const st = await c.links.reconcile("link-b");
    expect(st.pin).not.toBe(before?.pin);
    expect(listNodes(c.db)[0]?.pin).toBe(st.pin);
    expect(await Bun.file(`${node.nodeDir}/key.pem`).text()).not.toBe(keyBefore);
    expect((await Bun.file(`${node.nodeDir}/key.pem`).stat()).mode & 0o777).toBe(0o600);
    expect((await loadLinkTls(node.nodeDir)).cert).toBe(node.tls.cert);
    expect(await ping(c, "link-b")).toBe("pong");
  });

  test("core renewal hands the new pin to every node before switching", async () => {
    const c = await core();
    const a = await startNode(c, "link-c");
    const d = await startNode(c, "link-d");
    await c.links.reconcileAll();
    const old = c.identity.current().pin;
    expect(await c.links.renewCore()).toBe(true);
    const fresh = c.identity.current().pin;
    expect(fresh).not.toBe(old);
    expect(await pinsOn(a.nodeDir)).toEqual([fresh]);
    expect(await pinsOn(d.nodeDir)).toEqual([fresh]);
    expect(await ping(c, "link-c")).toBe("pong");
    expect(await ping(c, "link-d")).toBe("pong");
  });

  test("core renewal waits while a node is unreachable and the certificate has time left", async () => {
    const c = await core();
    await startNode(c, "link-e");
    const down = await startNode(c, "link-f");
    await c.links.reconcileAll();
    down.server.stop();
    const old = c.identity.current().pin;
    expect(await c.links.renewCore()).toBe(false);
    expect(c.identity.current().pin).toBe(old);
    expect(await ping(c, "link-e")).toBe("pong");
  });

  test("core renewal goes ahead without an unreachable node when 2 days are left", async () => {
    const clock = { now: Date.now() };
    const c = await core(signer, clock);
    const up = await startNode(c, "link-i");
    const down = await startNode(c, "link-j");
    await c.links.reconcileAll();
    down.server.stop();
    const old = c.identity.current().pin;
    clock.now = c.identity.current().notAfter - 86_400_000;
    expect(await c.links.renewCore()).toBe(true);
    expect(c.identity.current().pin).not.toBe(old);
    expect(await pinsOn(up.nodeDir)).toEqual([c.identity.current().pin]);
    expect(await pinsOn(down.nodeDir)).toEqual([old]);
    const checks = nodeChecks(
      listNodes(c.db),
      c.identity.current().ca,
      c.identity.current().pin,
      clock.now,
    );
    const links = checks.filter((x) => x.item.endsWith(" link"));
    expect(links.map((x) => [x.item, x.status])).toEqual([["link-j link", "fail"]]);
    expect(links[0]?.detail).toMatch(/bunzzle nodes remove link-j, then request, add and install/);
  });

  test("remove closes the link at once", async () => {
    const c = await core();
    await startNode(c, "link-g");
    const client = c.links.client("link-g");
    expect(await ping(c, "link-g")).toBe("pong");
    const hanging = client?.call("hang", {}, { timeoutMs: 30_000 }).catch((e: RpcError) => e.code);
    await Bun.sleep(50);
    await invoke(c.methods, "removeNode", { name: "link-g" });
    expect(await hanging).toBe("lost");
    expect(c.links.names()).toEqual([]);
  });

  test("CA rotation runs over the link: trust, promote with node renewal, finish", async () => {
    await Bun.$`mkdir -p ${dir}/rot-link`.quiet();
    const rotCa = await NodeCa.open(`${dir}/rot-link/node-ca.json`, master, null, Date.now());
    const c = await core(await startSigner(rotCa));
    const node = await startNode(c, "link-h");
    const step = (s: string) =>
      invoke(c.methods, "rotateNodeCa", { step: s }) as Promise<{
        pending: { step: string; nodes: string[] } | null;
      }>;

    expect((await step("start")).pending).toEqual({ step: "promote", nodes: [] });
    expect(fromPem(await Bun.file(`${node.nodeDir}/ca.pem`).text())).toHaveLength(2);
    expect(await ping(c, "link-h")).toBe("pong");

    expect((await step("promote")).pending).toEqual({ step: "finish", nodes: [] });
    const next = rotCa.states().find((s) => s.state === "active")?.name;
    expect(listNodes(c.db)[0]?.ca).toBe(next);
    expect(await ping(c, "link-h")).toBe("pong");

    expect((await step("finish")).pending).toBeNull();
    const left = fromPem(await Bun.file(`${node.nodeDir}/ca.pem`).text());
    expect(left.map((d) => parseCertificate(d).commonNames[0])).toEqual([next]);
    expect(await ping(c, "link-h")).toBe("pong");
  });
});

async function localDelivery(ips: string[]) {
  const socket = `/tmp/bunzzle-${crypto.randomUUID().slice(0, 8)}.sock`;
  const server = await serveRpc(socket, {
    ips: method(b.object({}), () => ips.map((ip) => ({ ip }))),
  });
  const client = new RpcClient(socket);
  cleanup.push(() => {
    client.close();
    server.stop();
  });
  return client;
}

describe("delivery fleet", () => {
  const LOCAL_IP = "203.0.113.1";
  const NODE_IP = "203.0.113.2";

  test("each IP goes to the delivery role that reports it", async () => {
    const c = await core();
    await startNode(c, "fleet-a", [NODE_IP]);
    const fleet = new DeliveryFleet({
      local: await localDelivery([LOCAL_IP]),
      links: c.links,
      log: quiet,
    });
    await fleet.check();
    expect(fleet.clientFor(NODE_IP).name).toBe("fleet-a");
    expect(fleet.clientFor(LOCAL_IP).name).toBe(LOCAL);
    expect(fleet.clientFor("default").name).toBe(LOCAL);
    expect(fleet.ready(NODE_IP) && fleet.ready(LOCAL_IP)).toBe(true);
    expect(await fleet.clientFor(NODE_IP).client.call("ping", {})).toBe("pong");
  });

  test("a node is down after 3 failed checks, its IPs pause, and it comes back", async () => {
    const c = await core();
    const node = await startNode(c, "fleet-b", [NODE_IP]);
    const fleet = new DeliveryFleet({
      local: await localDelivery([LOCAL_IP]),
      links: c.links,
      log: quiet,
      checkMs: 1_000,
    });
    await fleet.check();
    node.server.stop();
    c.links.client("fleet-b")?.close();
    await fleet.check();
    await fleet.check();
    expect(fleet.ready(NODE_IP)).toBe(true);
    await fleet.check();
    expect(fleet.ready(NODE_IP)).toBe(false);
    expect(fleet.ready(LOCAL_IP)).toBe(true);
    const down = fleet.health().find((h) => h.name === "fleet-b");
    expect(down?.up).toBe(false);
    expect(fleet.down(NODE_IP)?.reason).toBe(`node fleet-b is down (${NODE_IP})`);
    expect(Date.now() - (fleet.down(NODE_IP)?.since ?? 0)).toBeLessThan(5_000);
    const checks = fleetChecks(fleet.health(), fleet.conflicts(), [LOCAL_IP, NODE_IP], Date.now());
    expect(checks.find((x) => x.item === "fleet-b health")?.status).toBe("fail");

    await node.restart();
    await Bun.sleep(1_100);
    await fleet.check();
    expect(fleet.ready(NODE_IP)).toBe(true);
    expect(fleet.health().find((h) => h.name === "fleet-b")?.up).toBe(true);
  });

  test("a failed deliver marks the node down at once", async () => {
    const c = await core();
    await startNode(c, "fleet-c", [NODE_IP]);
    const fleet = new DeliveryFleet({ local: await localDelivery([]), links: c.links, log: quiet });
    await fleet.check();
    fleet.markDown("fleet-c", "unavailable");
    expect(fleet.ready(NODE_IP)).toBe(false);
  });

  test("an IP reported twice is paused and doctor names both", async () => {
    const c = await core();
    await startNode(c, "fleet-d", [NODE_IP, LOCAL_IP]);
    const fleet = new DeliveryFleet({
      local: await localDelivery([LOCAL_IP]),
      links: c.links,
      log: quiet,
    });
    await fleet.check();
    expect(fleet.ready(LOCAL_IP)).toBe(false);
    expect(fleet.ready(NODE_IP)).toBe(true);
    expect(fleet.conflicts()).toEqual([{ ip: LOCAL_IP, nodes: [LOCAL, "fleet-d"] }]);
    expect(fleet.down(LOCAL_IP)?.reason).toBe(`${LOCAL_IP} is on local and fleet-d`);
    const checks = fleetChecks(fleet.health(), fleet.conflicts(), [LOCAL_IP, NODE_IP], Date.now());
    expect(checks.find((x) => x.item === `${LOCAL_IP} owner`)?.detail).toMatch(/local and fleet-d/);
  });

  test("doctor fails a configured IP that no delivery role reports", async () => {
    const c = await core();
    await startNode(c, "fleet-e", [NODE_IP]);
    const fleet = new DeliveryFleet({ local: await localDelivery([]), links: c.links, log: quiet });
    await fleet.check();
    const checks = fleetChecks(fleet.health(), fleet.conflicts(), [LOCAL_IP, NODE_IP], Date.now());
    expect(checks.filter((x) => x.status === "fail").map((x) => x.item)).toEqual([
      `${LOCAL_IP} owner`,
    ]);
    expect(fleet.ready(LOCAL_IP)).toBe(false);
    expect(fleet.down(LOCAL_IP)?.reason).toBe(`no delivery role has ${LOCAL_IP}`);
  });

  test("a removed node leaves the fleet", async () => {
    const c = await core();
    await startNode(c, "fleet-f", [NODE_IP]);
    const fleet = new DeliveryFleet({ local: await localDelivery([]), links: c.links, log: quiet });
    await fleet.check();
    await invoke(c.methods, "removeNode", { name: "fleet-f" });
    await fleet.check();
    expect(fleet.health().map((h) => h.name)).toEqual([LOCAL]);
    expect(fleet.ready(NODE_IP)).toBe(false);
  });
});

describe("egress", () => {
  test("an egress is added, installed and reached over the node link, and the fleet checks it", async () => {
    const c = await core();
    const nodeDir = `${dir}/edge-a`;
    const csr = await requestCsr(nodeDir, "edge-a");
    const port = nextPort++;
    const result = (await invoke(c.methods, "addNode", {
      name: "edge-a",
      address: `127.0.0.1:${port}`,
      csr,
      kind: "egress",
    })) as { kind: string };
    expect(result.kind).toBe("egress");
    expect(listNodes(c.db).map((n) => [n.name, n.kind])).toEqual([["edge-a", "egress"]]);
    const listed = (await invoke(c.methods, "listNodes", {})) as { kind: string }[];
    expect(listed.map((n) => n.kind)).toEqual(["egress"]);

    await Bun.write(`${nodeDir}/bundle.json`, JSON.stringify(result));
    await nodesCommand(["install", `${nodeDir}/bundle.json`, "--dir", nodeDir], config);
    const server = await runEgress(
      {
        egressListen: { hostname: "127.0.0.1", port },
        nodeDir,
        sourceIps: [],
      } as unknown as Config,
      quiet,
    );
    cleanup.push(() => server.stop());

    expect(c.links.names()).toEqual(["edge-a"]);
    expect(c.links.names("delivery")).toEqual([]);
    expect(c.links.kindOf("edge-a")).toBe("egress");
    expect((await c.links.reconcile("edge-a")).name).toBe("edge-a");
    const client = c.links.client("edge-a") as RpcClient;
    const refused = await client.call("deliver", {}).catch((e: RpcError) => e.message);
    expect(refused).toBe("unknown method deliver");

    const fleet = new DeliveryFleet({
      local: { call: async () => [], close() {} } as never,
      links: c.links,
      log: quiet,
    });
    await fleet.check();
    expect(fleet.health().map((h) => [h.name, h.kind, h.up])).toEqual([
      [LOCAL, "delivery", true],
      ["edge-a", "egress", true],
    ]);
    expect(fleet.clientFor("203.0.113.77").name).toBe(LOCAL);
  });

  test("an egress needs BUNZZLE_EGRESS_LISTEN", async () => {
    const err = await runEgress(
      { egressListen: null, nodeDir: dir, sourceIps: [] } as unknown as Config,
      quiet,
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConfigError);
    expect((err as Error).message).toContain("BUNZZLE_EGRESS_LISTEN");
  });
});

async function startEgress(
  c: Awaited<ReturnType<typeof core>>,
  name: string,
  smtpPort = 25,
  sources: string[] = [],
) {
  const nodeDir = `${dir}/${name}-${crypto.randomUUID().slice(0, 6)}`;
  const port = nextPort++;
  const csr = await requestCsr(nodeDir, name);
  const bundle = await invoke(c.methods, "addNode", {
    name,
    address: `127.0.0.1:${port}`,
    csr,
    kind: "egress",
  });
  await Bun.write(`${nodeDir}/bundle.json`, JSON.stringify(bundle));
  await nodesCommand(["install", `${nodeDir}/bundle.json`, "--dir", nodeDir], config);
  const run = () =>
    runEgress(
      {
        egressListen: { hostname: "127.0.0.1", port },
        nodeDir,
        smtpPort,
        sourceIps: sources.map((ip) => ({ ip })),
      } as unknown as Config,
      quiet,
    );
  const e = { server: await run(), port, restart: async () => (e.server = await run()) };
  cleanup.push(() => e.server.stop());
  return e;
}

function asDelivery(c: Awaited<ReturnType<typeof core>>, name: string, port: number) {
  const me = c.deliveryIdentity.current();
  if (!me) throw new Error("delivery has no link certificate");
  const egress = listNodes(c.db).find((n) => n.name === name);
  const client = new RpcClient({
    hostname: "127.0.0.1",
    port,
    tls: { cert: me.cert, key: me.key, ca: me.ca, pins: [egress?.pin ?? ""], name },
  });
  cleanup.push(() => client.close());
  return client;
}

const statusOfLink = (c: Awaited<ReturnType<typeof core>>, name: string) =>
  (c.links.client(name) as RpcClient).call<{ corePins: string[]; deliveryPins: string[] }>(
    "linkStatus",
    {},
  );

describe("delivery link certificate", () => {
  test("the delivery pin reaches an egress but may not call link methods", async () => {
    const c = await core();
    const e = await startEgress(c, "edge-l");
    expect(await c.deliveryLink.upkeep()).toBe(true);
    const pin = c.deliveryIdentity.current()?.pin as string;
    expect(c.deliveryLink.pins()).toEqual([pin]);
    expect((await statusOfLink(c, "edge-l")).deliveryPins).toEqual([pin]);

    const d = asDelivery(c, "edge-l", e.port);
    for (const [m, params] of [
      ["linkStatus", {}],
      ["trustCorePins", { pins: [pin] }],
      ["trustDeliveryPins", { pins: [] }],
      ["trustCas", { ca: "x" }],
      ["renewRequest", {}],
      ["renewInstall", { cert: "x", ca: "x" }],
    ] as const) {
      const err = await d.call(m, params).catch((x: RpcError) => x);
      expect(err).toMatchObject({ code: "forbidden" });
    }
    expect((await statusOfLink(c, "edge-l")).corePins).toEqual([c.identity.current().pin]);
    expect(await c.deliveryLink.upkeep()).toBe(false);
  });

  test("renewal waits while an egress is down, unless the certificate is close to expiry", async () => {
    const c = await core();
    await startEgress(c, "edge-u");
    const down = await startEgress(c, "edge-d");
    await c.deliveryLink.upkeep();
    const first = c.deliveryIdentity.current()?.pin as string;
    down.server.stop();
    c.links.close("edge-d");

    c.clock.now += 2 * DAY_MS;
    expect(await c.deliveryLink.upkeep()).toBe(false);
    expect(c.deliveryIdentity.current()?.pin).toBe(first);
    expect((await statusOfLink(c, "edge-u")).deliveryPins).toEqual([first]);

    c.clock.now += 4 * DAY_MS;
    expect(await c.deliveryLink.upkeep()).toBe(true);
    const second = c.deliveryIdentity.current()?.pin as string;
    expect(second).not.toBe(first);
    expect((await statusOfLink(c, "edge-u")).deliveryPins).toEqual([second]);

    await down.restart();
    c.links.close("edge-d");
    c.links.sync();
    await c.links.reconcile("edge-d");
    expect((await statusOfLink(c, "edge-d")).deliveryPins).toEqual([second]);
  });

  test("CA rotation reissues the delivery certificate from the new CA", async () => {
    const rotCa = await NodeCa.open(`${dir}/rot-d/node-ca.json`, master, null, Date.now());
    const client = await startSigner(rotCa);
    const c = await core(client);
    const e = await startEgress(c, "edge-r");
    await c.deliveryLink.upkeep();
    const step = (s: string) => invoke(c.methods, "rotateNodeCa", { step: s });
    await step("start");
    await c.links.reconcile("edge-r");
    await step("promote");
    const next = rotCa.states().find((s) => s.state === "active")?.name;
    expect(c.deliveryIdentity.current()?.issuer).toBe(next);
    const err = await asDelivery(c, "edge-r", e.port)
      .call("linkStatus", {})
      .catch((x: RpcError) => x);
    expect(err).toMatchObject({ code: "forbidden" });
  });

  test("doctor fails without a delivery link certificate once an egress exists", () => {
    const egress = {
      name: "edge-x",
      kind: "egress" as const,
      address: "127.0.0.1:7465",
      pin: "sha256/x",
      notAfter: Date.now() + 20 * DAY_MS,
      ca: "",
      trustedCas: [],
      corePins: [],
      createdAt: 0,
    };
    const checks = (link: number | null) =>
      nodeChecks([egress], "", "sha256/core", Date.now(), link).filter(
        (x) => x.item === "delivery link certificate",
      );
    expect(checks(null).map((x) => x.status)).toEqual(["fail"]);
    expect(checks(Date.now() + DAY_MS).map((x) => x.status)).toEqual(["warn"]);
    expect(checks(Date.now() + 6 * DAY_MS).map((x) => x.status)).toEqual(["ok"]);
    expect(
      nodeChecks([{ ...egress, kind: "delivery" }], "", "sha256/core", Date.now(), null).filter(
        (x) => x.item === "delivery link certificate",
      ),
    ).toEqual([]);
  });
});

const DAY_MS = 86_400_000;

const MESSAGE = "From: a@bunzzle.com\r\nTo: b@example.test\r\nSubject: Hi\r\n\r\nHello\r\n";

async function throughEgress(scenario: MxScenario = {}, mxPort?: number) {
  const mx: FakeMx | null = mxPort === undefined ? startFakeMx(scenario) : null;
  if (mx) cleanup.push(() => mx.stop());
  const smtpPort = mx?.port ?? (mxPort as number);
  const c = await core();
  const e = await startEgress(c, "edge-s", smtpPort);
  await c.deliveryLink.upkeep();
  const me = c.deliveryIdentity.current();
  const node = listNodes(c.db).find((n) => n.name === "edge-s");
  if (!me || !node) throw new Error("egress not ready");
  const tls = { cert: me.cert, key: me.key, ca: me.ca, pins: [node.pin], name: "edge-s" };
  const via = egressVia("edge-s", { hostname: "127.0.0.1", port: e.port, tls }, dir);
  const session = (o: Partial<SessionInput> = {}) =>
    runSession({
      host: "mx.example.test",
      address: "127.0.0.1",
      port: smtpPort,
      localAddress: "127.0.0.1",
      via,
      ehloName: "out.bunzzle.test",
      policy: { rule: "opportunistic", required: false },
      from: "a@bunzzle.com",
      recipients: ["b@example.test"],
      data: MESSAGE,
      smtpUtf8: false,
      tlsCa: TEST_CA,
      timeouts: { greeting: 2000, quit: 200 },
      ...o,
    });
  return { c, e, mx, via, session };
}

describe("sending through an egress", () => {
  test("STARTTLS runs end to end and the email is delivered", async () => {
    const t = await throughEgress();
    const r = await t.session();
    expect(r.phase).toBe("done");
    expect(r.recipients.map((x) => x.status)).toEqual(["delivered"]);
    expect(r.tls.status).toBe("verified");
    expect(t.mx?.sessions[0]?.tls).toBe(true);
    expect(t.mx?.sessions[0]?.messages).toEqual([MESSAGE]);
    expect(r.transcript?.[0]?.[2]).toMatch(
      /^connected to 127\.0\.0\.1:\d+ from 127\.0\.0\.1 through edge-s$/,
    );
  });

  test("a connection through an egress is reused", async () => {
    const t = await throughEgress();
    const pool = new SessionPool();
    const first = await t.session({ pool });
    const second = await t.session({ pool });
    expect([first.reused ?? false, second.reused]).toEqual([false, true]);
    expect(t.mx?.sessions.length).toBe(1);
    await pool.closeAll();
  });

  test("the egress refuses any port but the SMTP port", async () => {
    const t = await throughEgress();
    const err = await t.via.open("127.0.0.1", 587, "127.0.0.1", 2000).catch((x: Error) => x);
    expect((err as Error).message).toBe(`only port ${t.mx?.port} is allowed`);
  });

  test("a refused connection behind the egress is deferred like a local one", async () => {
    const closed = startFakeMx();
    const port = closed.port;
    closed.stop();
    const t = await throughEgress({}, port);
    const r = await t.session();
    expect(r.phase).toBe("connect");
    expect(r.recipients.map((x) => x.status)).toEqual(["deferred"]);
    expect(r.error).toContain("through edge-s");
  });

  test("an egress that stops after the end of data leaves the recipient unknown", async () => {
    const t = await throughEgress({ finalDelayMs: 1500 });
    setTimeout(() => t.e.server.stop(), 500);
    const r = await t.session({ timeouts: { greeting: 2000, quit: 200, dataDone: 5000 } });
    expect(r.recipients.map((x) => x.status)).toEqual(["unknown"]);
    expect(r.phase).toBe("dot");
  });

  test("an egress that stops before the end of data leaves the recipient deferred", async () => {
    const silent = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
    cleanup.push(() => silent.stop(true));
    const t = await throughEgress({}, silent.port);
    setTimeout(() => t.e.server.stop(), 300);
    const r = await t.session({ timeouts: { greeting: 5000, quit: 200 } });
    expect(r.recipients.map((x) => x.status)).toEqual(["deferred"]);
  });
});

describe("egresses in the fleet", () => {
  const fleetFor = (c: Awaited<ReturnType<typeof core>>, up: string[] = []) =>
    new DeliveryFleet({
      local: { call: async () => [], close() {} } as never,
      links: c.links,
      log: quiet,
      onUp: (name) => up.push(name),
    });

  test("an egress reports the IPs it can bind and core sends them through it", async () => {
    const c = await core();
    const e = await startEgress(c, "edge-f", 25, ["127.0.0.1", "203.0.113.200"]);
    const fleet = fleetFor(c);
    await fleet.check();
    expect(fleet.health().find((h) => h.name === "edge-f")?.ips).toEqual(["127.0.0.1"]);
    const pin = listNodes(c.db).find((n) => n.name === "edge-f")?.pin;
    expect(fleet.clientFor("127.0.0.1")).toMatchObject({
      name: LOCAL,
      egress: { name: "edge-f", address: `127.0.0.1:${e.port}`, pin },
    });
    expect(fleet.nodeOf("127.0.0.1")).toBe("edge-f");
    expect(fleet.down("127.0.0.1")).toBeNull();
  });

  test("a stopped egress makes its IPs wait with its name and wakes them when back", async () => {
    const c = await core();
    const e = await startEgress(c, "edge-w", 25, ["127.0.0.1"]);
    const up: string[] = [];
    const fleet = fleetFor(c, up);
    await fleet.check();
    const start = up.length;
    e.server.stop();
    for (let i = 0; i < 3; i++) await fleet.check();
    expect(fleet.down("127.0.0.1")).toMatchObject({
      reason: "egress edge-w is down (127.0.0.1)",
      node: "edge-w",
    });
    await e.restart();
    c.links.close("edge-w");
    await fleet.check();
    expect(fleet.down("127.0.0.1")).toBeNull();
    expect(up.slice(start)).toEqual(["edge-w"]);
  });
});
