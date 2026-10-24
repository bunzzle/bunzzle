import { afterEach, describe, expect, test } from "bun:test";
import { pem } from "../../src/asn1/der.ts";
import { method, pinOf, RpcClient, type RpcServer, serveRpc } from "../../src/ipc/rpc.ts";
import { b } from "../../src/validate/schema.ts";
import { KEY_CERT_SIGN, parseCertificate } from "../../src/x509/cert.ts";
import {
  certificateRequest,
  distinguishedName,
  issueCertificate,
  type Purpose,
  parseCertificateRequest,
  signWith,
} from "../../src/x509/issue.ts";
import { verifySignature } from "../../src/x509/verify.ts";
import { freePort } from "../support/ports.ts";

const DAY = 86_400_000;
const now = Date.now();

const keyPair = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;
const spkiOf = async (k: CryptoKeyPair) =>
  new Uint8Array(await crypto.subtle.exportKey("spki", k.publicKey));
const keyPem = async (k: CryptoKeyPair) =>
  pem("PRIVATE KEY", new Uint8Array(await crypto.subtle.exportKey("pkcs8", k.privateKey)));

const caKey = await keyPair();
const caName = distinguishedName("bunzzle-node-ca");
const caCert = await issueCertificate({
  name: "bunzzle-node-ca",
  spki: await spkiOf(caKey),
  purpose: "ca",
  issuer: caName,
  sign: signWith(caKey.privateKey),
  notBefore: now,
  notAfter: now + 730 * DAY,
});

async function leaf(name: string, purpose: Purpose, days = 30) {
  const key = await keyPair();
  const csr = await parseCertificateRequest(await certificateRequest(name, key));
  const der = await issueCertificate({
    ...csr,
    purpose,
    issuer: caName,
    sign: signWith(caKey.privateKey),
    notBefore: now - 60_000,
    notAfter: now + days * DAY,
  });
  return { der, key, spki: csr.spki };
}

const servers: RpcServer[] = [];
const clients: RpcClient[] = [];

afterEach(() => {
  for (const s of servers.splice(0)) s.stop();
  for (const c of clients.splice(0)) c.close();
});

describe("node certificates", () => {
  test("CA certificate is self-signed, CA only, path length 0", async () => {
    const cert = parseCertificate(caCert);
    expect(cert.ca).toBe(true);
    expect(cert.pathLen).toBe(0);
    expect((cert.keyUsage ?? 0) & KEY_CERT_SIGN).toBe(KEY_CERT_SIGN);
    expect(cert.extKeyUsage).toBeNull();
    expect(cert.commonNames).toEqual(["bunzzle-node-ca"]);
    expect(await verifySignature(cert, cert.spki)).toBe(true);
  });

  test("request round trip keeps the name and key", async () => {
    const key = await keyPair();
    const csr = await parseCertificateRequest(await certificateRequest("node-1", key));
    expect(csr.name).toBe("node-1");
    expect(csr.spki).toEqual(await spkiOf(key));
  });

  test("tampered request is refused", async () => {
    const der = await certificateRequest("node-1", await keyPair());
    const at = der.indexOf(0x2d);
    der[at] = 0x5f;
    await expect(parseCertificateRequest(der)).rejects.toThrow(/signature|name/);
  });

  test("bad names are refused", async () => {
    const key = await keyPair();
    for (const name of ["", "Node", "-a", "a_b", "a".repeat(64)]) {
      await expect(certificateRequest(name, key)).rejects.toThrow(/bad node name/);
    }
  });

  test("leaf certificate has one purpose and the CA as issuer", async () => {
    const node = await leaf("node-1", "server");
    const cert = parseCertificate(node.der);
    expect(cert.ca).toBe(false);
    expect(cert.extKeyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
    expect(cert.commonNames).toEqual(["node-1"]);
    expect(cert.issuer).toEqual(caName);
    expect(cert.notAfter - cert.notBefore).toBeGreaterThan(29 * DAY);
    expect(await verifySignature(cert, parseCertificate(caCert).spki)).toBe(true);
  });

  test("validity after 2049 uses GeneralizedTime", async () => {
    const node = await leaf("node-1", "server", 30_000);
    expect(parseCertificate(node.der).notAfter).toBeGreaterThan(Date.UTC(2050, 0, 1));
  });

  test("issued certificates work for mutual TLS", async () => {
    const node = await leaf("node-1", "server");
    const core = await leaf("core", "client");
    const ca = pem("CERTIFICATE", caCert);
    const port = freePort();
    servers.push(
      await serveRpc(
        {
          hostname: "127.0.0.1",
          port,
          tls: {
            cert: pem("CERTIFICATE", node.der),
            key: await keyPem(node.key),
            ca,
            pins: [pinOf(core.spki)],
          },
        },
        { add: method(b.object({ a: b.number(), b: b.number() }), ({ a, b }) => a + b) },
      ),
    );
    const c = new RpcClient({
      hostname: "127.0.0.1",
      port,
      tls: {
        cert: pem("CERTIFICATE", core.der),
        key: await keyPem(core.key),
        ca,
        pins: [pinOf(node.spki)],
        name: "node-1",
      },
    });
    clients.push(c);
    expect(await c.call("add", { a: 2, b: 3 })).toBe(5);
  });
});
