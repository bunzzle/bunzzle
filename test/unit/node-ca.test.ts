import { afterAll, describe, expect, test } from "bun:test";
import { fromPem } from "../../src/asn1/der.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import type { KeyStore } from "../../src/dkim/store.ts";
import { NodeCa } from "../../src/signer/node-ca.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { signWith } from "../../src/x509/issue.ts";
import { verifySignature } from "../../src/x509/verify.ts";

const DAY = 86_400_000;
const now = Date.UTC(2026, 9, 23);
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-node-ca-${crypto.randomUUID()}`;
const master = await masterKeyFrom(generateMasterKey());

afterAll(async () => {
  await Bun.$`rm -rf ${dir}`.quiet();
});

const p256 = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]) as Promise<CryptoKeyPair>;
const spkiOf = async (k: CryptoKeyPair) =>
  new Uint8Array(await crypto.subtle.exportKey("spki", k.publicKey));
const first = (text: string) => parseCertificate(fromPem(text)[0] as Uint8Array);

function memoryStore(): KeyStore & { names: string[] } {
  const keys = new Map<string, CryptoKeyPair>();
  return {
    names: [],
    async create() {
      throw new Error("not used");
    },
    key() {
      throw new Error("not used");
    },
    async createP256(name) {
      const pair = await p256();
      keys.set(name, pair);
      this.names.push(name);
      return spkiOf(pair);
    },
    signerP256(name) {
      return (data) => {
        const pair = keys.get(name);
        if (!pair) throw new Error(`no key ${name}`);
        return signWith(pair.privateKey)(data);
      };
    },
  };
}

describe("node CA", () => {
  test("first open creates a 2-year P-256 CA sealed with the master key", async () => {
    const path = `${dir}/a/node-ca.json`;
    await Bun.$`mkdir -p ${dir}/a`.quiet();
    const ca = await NodeCa.open(path, master, null, now);
    const cert = first(ca.trusted());
    expect(cert.ca).toBe(true);
    expect(cert.commonNames[0]).toMatch(/^bunzzle-node-ca-[0-9a-f]{8}$/);
    expect(cert.notAfter - now).toBe(730 * DAY);
    expect((await Bun.$`stat -f %Lp ${path}`.text()).trim()).toBe("600");
    const file = await Bun.file(path).json();
    expect(file.cas[0].sealedKey).toBeString();
    expect(JSON.stringify(file)).not.toContain("PRIVATE KEY");
  });

  test("reopen keeps the same CA and issues certificates it signed", async () => {
    const path = `${dir}/b/node-ca.json`;
    await Bun.$`mkdir -p ${dir}/b`.quiet();
    const trusted = (await NodeCa.open(path, master, null, now)).trusted();
    const ca = await NodeCa.open(path, master, null, now + DAY);
    expect(ca.trusted()).toBe(trusted);
    const node = await spkiOf(await p256());
    const cert = first(await ca.issue("node-1", node, "server", 30, now + DAY));
    expect(cert.commonNames).toEqual(["node-1"]);
    expect(cert.extKeyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
    expect(cert.notAfter - (now + DAY)).toBe(30 * DAY);
    expect(cert.issuer).toEqual(first(trusted).subject);
    expect(await verifySignature(cert, first(trusted).spki)).toBe(true);
  });

  test("certificates never outlive the CA", async () => {
    const path = `${dir}/c/node-ca.json`;
    await Bun.$`mkdir -p ${dir}/c`.quiet();
    const ca = await NodeCa.open(path, master, null, now);
    const later = now + 720 * DAY;
    const cert = first(await ca.issue("node-1", await spkiOf(await p256()), "client", 30, later));
    expect(cert.notAfter).toBe(first(ca.trusted()).notAfter);
  });

  test("another master key cannot open the CA", async () => {
    const path = `${dir}/d/node-ca.json`;
    await Bun.$`mkdir -p ${dir}/d`.quiet();
    await NodeCa.open(path, master, null, now);
    const other = await masterKeyFrom(generateMasterKey());
    await expect(NodeCa.open(path, other, null, now)).rejects.toThrow(/another master key/);
  });

  test("with a key store the CA key lives only in the store", async () => {
    const path = `${dir}/e/node-ca.json`;
    await Bun.$`mkdir -p ${dir}/e`.quiet();
    const store = memoryStore();
    const ca = await NodeCa.open(path, master, store, now);
    const file = await Bun.file(path).json();
    expect(file.cas[0].sealedKey).toBeUndefined();
    expect(file.cas[0].storeKey).toBe(store.names[0]);
    const reopened = await NodeCa.open(path, master, store, now);
    const cert = first(await reopened.issue("core", await spkiOf(await p256()), "client", 7, now));
    expect(await verifySignature(cert, first(ca.trusted()).spki)).toBe(true);
    await expect(NodeCa.open(path, master, null, now)).rejects.toThrow(/key store/);
  });
});
