import { afterAll, describe, expect, test } from "bun:test";
import { fromPem } from "../../src/asn1/der.ts";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { transitStore } from "../../src/dkim/store.ts";
import { verifyDkim } from "../../src/dkim/verify.ts";
import { NodeCa } from "../../src/signer/node-ca.ts";
import { Signer } from "../../src/signer/signer.ts";
import { parseCertificate } from "../../src/x509/cert.ts";
import { verifySignature } from "../../src/x509/verify.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-store-${crypto.randomUUID()}`;
const socket = `/tmp/bunzzle-${crypto.randomUUID().slice(0, 8)}.sock`;
const pairs = new Map<string, { type: string; pair: CryptoKeyPair }>();
const requests: { method: string; path: string; body: Record<string, unknown> | null }[] = [];
let down = false;

const store = Bun.serve({
  unix: socket,
  async fetch(req) {
    const path = new URL(req.url).pathname;
    const body = req.method === "POST" ? ((await req.json()) as Record<string, unknown>) : null;
    requests.push({ method: req.method, path, body });
    if (down) return Response.json({ errors: ["sealed"] }, { status: 503 });
    const keyName = /^\/v1\/transit\/keys\/([^/]+)$/.exec(path)?.[1];
    if (keyName && req.method === "POST") {
      const name = decodeURIComponent(keyName);
      if (!pairs.has(name)) {
        const rsa = body?.["type"] === "rsa-2048";
        const pair = (
          body?.["type"] === "ecdsa-p256"
            ? await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
                "sign",
                "verify",
              ])
            : rsa
              ? await crypto.subtle.generateKey(
                  {
                    name: "RSASSA-PKCS1-v1_5",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                  },
                  true,
                  ["sign", "verify"],
                )
              : await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])
        ) as CryptoKeyPair;
        pairs.set(name, { type: body?.["type"] as string, pair });
      }
      return new Response(null, { status: 204 });
    }
    if (keyName) {
      const k = pairs.get(decodeURIComponent(keyName));
      if (!k) return Response.json({ errors: [] }, { status: 404 });
      const rsa = k.type === "rsa-2048" || k.type === "ecdsa-p256";
      const pub = new Uint8Array(
        await crypto.subtle.exportKey(rsa ? "spki" : "raw", k.pair.publicKey),
      ).toBase64();
      const public_key = rsa
        ? `-----BEGIN PUBLIC KEY-----\n${pub.match(/.{1,64}/g)?.join("\n")}\n-----END PUBLIC KEY-----\n`
        : pub;
      return Response.json({
        data: { type: k.type, latest_version: 1, keys: { "1": { public_key } } },
      });
    }
    const signName = /^\/v1\/transit\/sign\/([^/]+)\/sha2-256$/.exec(path)?.[1];
    const k = signName ? pairs.get(decodeURIComponent(signName)) : undefined;
    if (!k) return Response.json({ errors: ["no route"] }, { status: 404 });
    const rsa = k.type === "rsa-2048";
    if (rsa && body?.["signature_algorithm"] !== "pkcs1v15") {
      return Response.json({ errors: ["pss"] }, { status: 400 });
    }
    const input = Uint8Array.fromBase64(body?.["input"] as string);
    if (k.type === "ecdsa-p256") {
      if (body?.["marshaling_algorithm"] !== "jws") {
        return Response.json({ errors: ["asn1"] }, { status: 400 });
      }
      const raw = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.pair.privateKey, input),
      );
      return Response.json({
        data: {
          signature: `vault:v1:${raw.toBase64({ alphabet: "base64url", omitPadding: true })}`,
        },
      });
    }
    const sig = await crypto.subtle.sign(
      rsa ? "RSASSA-PKCS1-v1_5" : "Ed25519",
      k.pair.privateKey,
      input,
    );
    return Response.json({ data: { signature: `vault:v1:${new Uint8Array(sig).toBase64()}` } });
  },
});

afterAll(async () => {
  store.stop(true);
  await Bun.$`rm -rf ${dir} ${socket}`.quiet();
});

const master = await masterKeyFrom(generateMasterKey());
const options = (withStore: boolean, files: string[] = []) => ({
  master,
  keystorePath: `${dir}/epochs.json`,
  dkimKeyFiles: files,
  dkimDir: `${dir}/dkim`,
  store: withStore ? transitStore(socket) : null,
});

async function verified(signer: Signer, which: "active" | "next" = "active") {
  const signed = await signer.signCanary("acme.test", which);
  const keys = Object.fromEntries(
    (signer.publicKeys("acme.test") ?? []).map((k) => [
      k.selector,
      { algorithm: k.algorithm, key: Uint8Array.fromBase64(k.publicKey) },
    ]),
  );
  return verifyDkim(signed, keys);
}

describe("DKIM keys in an external key store", () => {
  test("new keys are created in the store and only their names and public keys are saved", async () => {
    const signer = await Signer.create(options(true));
    const keys = await signer.ensureKeys("acme.test", "b1");
    expect(keys.map((k) => k.selector)).toEqual(["b1r", "b1e"]);
    expect([...pairs.keys()]).toEqual(["bunzzle-dkim-acme.test-b1r", "bunzzle-dkim-acme.test-b1e"]);
    expect(requests[0]?.body).toEqual({ type: "rsa-2048", exportable: false });
    const saved = await Bun.file(`${dir}/dkim/acme.test.json`).text();
    expect(saved).toContain('"storeKey": "bunzzle-dkim-acme.test-b1r"');
    expect(saved).not.toContain("privateKey");
    expect(saved).not.toContain("PrivateKey");
    expect(await verified(signer)).toEqual([
      { selector: "b1r", ok: true },
      { selector: "b1e", ok: true },
    ]);
  });

  test("rotation creates the next keys in the store", async () => {
    const signer = await Signer.create(options(true, [`${dir}/dkim/acme.test.json`]));
    await signer.rotateStart("acme.test", "b2");
    expect(pairs.has("bunzzle-dkim-acme.test-b2e")).toBe(true);
    expect((await verified(signer, "next")).every((v) => v.ok)).toBe(true);
    await signer.promote("acme.test");
    const v = await verified(signer);
    expect(v.map((x) => x.selector)).toEqual(["b2r", "b2e"]);
    expect(v.every((x) => x.ok)).toBe(true);
  });

  test("a key file with store keys needs the store; a store that is down fails signing", async () => {
    await expect(Signer.create(options(false, [`${dir}/dkim/acme.test.json`]))).rejects.toThrow(
      "BUNZZLE_DKIM_STORE_SOCKET",
    );
    const signer = await Signer.create(options(true, [`${dir}/dkim/acme.test.json`]));
    down = true;
    try {
      await expect(signer.signCanary("acme.test", "active")).rejects.toThrow(
        "the key store answered 503: sealed",
      );
    } finally {
      down = false;
    }
  });

  test("node CA key is created as P-256 in the store and signs certificates", async () => {
    const path = `${dir}/node-ca.json`;
    await Bun.$`mkdir -p ${dir}`.quiet();
    const ca = await NodeCa.open(path, master, transitStore(socket), Date.now());
    const file = await Bun.file(path).json();
    expect(file.cas[0].sealedKey).toBeUndefined();
    const created = requests.find(
      (r) => r.method === "POST" && r.path.endsWith(`/keys/${file.cas[0].storeKey}`),
    );
    expect(created?.body).toEqual({ type: "ecdsa-p256", exportable: false });
    const caCert = parseCertificate(fromPem(ca.trusted())[0] as Uint8Array);
    expect(await verifySignature(caCert, caCert.spki)).toBe(true);
  });
});
