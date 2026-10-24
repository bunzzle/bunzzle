import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { fromPem } from "../../src/asn1/der.ts";
import { egressVia } from "../../src/egress/tunnel.ts";
import { type LinkTls, pinOf, RpcClient, type RpcError } from "../../src/ipc/rpc.ts";
import { runSession } from "../../src/smtp/session.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { type FakeMx, startFakeMx, TEST_CA } from "../support/fake-mx.ts";
import { freePort } from "../support/ports.ts";

const fixtures = `${import.meta.dir}/../fixtures/node`;
const read = (name: string) => Bun.file(`${fixtures}/${name}`).text();
const pinIn = async (name: string) =>
  pinOf(parseCertificate(fromPem(await read(name))[0] as Uint8Array).spki);
const main = new URL("../../src/cli/main.ts", import.meta.url).pathname;
const base = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-egress-${crypto.randomUUID().slice(0, 8)}`;
const MESSAGE = "From: a@bunzzle.com\r\nTo: b@example.test\r\nSubject: Hi\r\n\r\nHello\r\n";

const ca = await read("ca.pem");
const core = { cert: await read("core.pem"), key: await read("core.key") };
const nodePin = await pinIn("node.pem");
const cleanup: (() => void)[] = [];

afterEach(() => {
  for (const c of cleanup.splice(0)) c();
});
afterAll(async () => {
  await Bun.$`rm -rf ${base}`.quiet().nothrow();
});

async function startEgress(mx: FakeMx) {
  const dir = `${base}/${crypto.randomUUID().slice(0, 8)}`;
  await Bun.$`mkdir -p ${dir} && chmod 700 ${dir}`.quiet();
  await Bun.write(`${dir}/cert.pem`, await read("node.pem"));
  await Bun.write(`${dir}/key.pem`, await read("node.key"));
  await Bun.$`chmod 600 ${dir}/key.pem`.quiet();
  await Bun.write(`${dir}/ca.pem`, ca);
  await Bun.write(`${dir}/peer.pin`, `${await pinIn("core.pem")}\n`);
  const port = freePort();
  const proc = Bun.spawn([process.execPath, main, "egress"], {
    env: {
      ...Bun.env,
      BUNZZLE_EGRESS_LISTEN: `127.0.0.1:${port}`,
      BUNZZLE_NODE_DIR: dir,
      BUNZZLE_SMTP_PORT: String(mx.port),
      BUNZZLE_SOURCE_IPS: "127.0.0.1",
      BUNZZLE_LOG_LEVEL: "info",
    },
    stdout: "pipe",
    stderr: "inherit",
  });
  cleanup.push(() => proc.kill("SIGKILL"));
  const reader = proc.stdout.getReader();
  let seen = "";
  while (!seen.includes("egress ready")) {
    const { value, done } = await reader.read();
    if (done) throw new Error(`egress exited: ${seen}`);
    seen += new TextDecoder().decode(value);
  }
  return { proc, port };
}

const link = (port: number, tls: Partial<LinkTls> = {}) => ({
  hostname: "127.0.0.1",
  port,
  tls: { ...core, ca, pins: [nodePin], name: "node-1", ...tls },
});

function session(mx: FakeMx, port: number, timeouts = {}) {
  return runSession({
    host: "mx.example.test",
    address: "127.0.0.1",
    port: mx.port,
    localAddress: "127.0.0.1",
    via: egressVia("edge-p", link(port), base),
    ehloName: "out.bunzzle.test",
    policy: { rule: "opportunistic", required: false },
    from: "a@bunzzle.com",
    recipients: ["b@example.test"],
    data: MESSAGE,
    smtpUtf8: false,
    tlsCa: TEST_CA,
    timeouts: { greeting: 3000, quit: 200, ...timeouts },
  });
}

describe("bunzzle egress as its own process", () => {
  test("mail goes through it with STARTTLS end to end, and it reports its IPs", async () => {
    const mx = startFakeMx();
    cleanup.push(() => mx.stop());
    const e = await startEgress(mx);
    const r = await session(mx, e.port);
    expect(r.error).toBeNull();
    expect(r.recipients.map((x) => x.status)).toEqual(["delivered"]);
    expect(r.tls.status).toBe("verified");
    expect(mx.sessions[0]?.messages).toEqual([MESSAGE]);
    const client = new RpcClient(link(e.port));
    cleanup.push(() => client.close());
    expect(await client.call("ips", {})).toEqual([{ ip: "127.0.0.1" }]);
  });

  test("killed after the end of data, the recipient is unknown", async () => {
    const mx = startFakeMx({ finalDelayMs: 2000 });
    cleanup.push(() => mx.stop());
    const e = await startEgress(mx);
    setTimeout(() => e.proc.kill("SIGKILL"), 700);
    const r = await session(mx, e.port, { dataDone: 5000 });
    expect(r.recipients.map((x) => x.status)).toEqual(["unknown"]);
  });

  test("a peer whose key it does not pin, or that pins another key, is refused", async () => {
    const mx = startFakeMx();
    cleanup.push(() => mx.stop());
    const e = await startEgress(mx);
    const other = { cert: await read("core-other-ca.pem"), key: await read("core.key") };
    const stranger = new RpcClient(link(e.port, other));
    const wrongPin = new RpcClient(link(e.port, { pins: [await pinIn("core.pem")] }));
    cleanup.push(() => {
      stranger.close();
      wrongPin.close();
    });
    for (const c of [stranger, wrongPin]) {
      const err = await c.call("ips", {}).catch((x: RpcError) => x);
      expect((err as RpcError).code).toMatch(/^(unavailable|lost)$/);
    }
  });
});
