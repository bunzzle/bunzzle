import { describe, expect, test } from "bun:test";
import { csr, dnsChallengeValue, newKeyPair } from "../../src/acme/client.ts";
import { certificateState, ensureCertificate } from "../../src/acme/manager.ts";
import { fromPem, notAfter, tlv } from "../../src/asn1/der.ts";
import type { RequestInput, RequestResult } from "../../src/net/request.ts";

const TLS = `${import.meta.dir}/../fixtures/tls`;
const CERT = await Bun.file(`${TLS}/mx.pem`).text();
const silent = { debug() {}, info() {}, warn() {}, error() {}, child: () => silent } as never;
const dec = new TextDecoder();
const b64uDecode = (s: string) => Uint8Array.fromBase64(s, { alphabet: "base64url" });

function fakeAcme() {
  const base = "https://acme.test";
  let nonce = 0;
  let accountJwk: Record<string, string> | null = null;
  const txt = new Map<string, string>();
  const state = {
    order: "pending",
    auth: new Map<string, string>(),
    csr: null as Uint8Array | null,
    requests: 0,
  };
  const hosts = ["in.acme.test", "smtp.acme.test"];
  const tokens = new Map(hosts.map((h, i) => [h, `token-${i}`]));
  const reply = (
    status: number,
    body: unknown,
    headers: Record<string, string> = {},
  ): RequestResult => ({
    ok: true,
    status,
    headers: new Map(Object.entries({ "replay-nonce": `n${++nonce}`, ...headers })),
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  const verify = async (input: RequestInput) => {
    const jws = JSON.parse(input.body ?? "{}") as {
      protected: string;
      payload: string;
      signature: string;
    };
    const header = JSON.parse(dec.decode(b64uDecode(jws.protected))) as {
      alg: string;
      url: string;
      jwk?: Record<string, string>;
      kid?: string;
    };
    expect(header.alg).toBe("ES256");
    expect(header.url).toBe(input.url);
    if (header.jwk) accountJwk = header.jwk;
    const key = await crypto.subtle.importKey(
      "jwk",
      { ...(accountJwk as object), key_ops: ["verify"] } as never,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64uDecode(jws.signature),
      new TextEncoder().encode(`${jws.protected}.${jws.payload}`),
    );
    expect(ok).toBe(true);
    return jws.payload ? JSON.parse(dec.decode(b64uDecode(jws.payload))) : "";
  };
  const request = async (input: RequestInput): Promise<RequestResult> => {
    state.requests++;
    const path = input.url.slice(base.length);
    if (input.method === "GET" && path === "/directory") {
      return reply(200, {
        newNonce: `${base}/nonce`,
        newAccount: `${base}/account`,
        newOrder: `${base}/order`,
      });
    }
    if (input.method === "GET" && path === "/nonce") return reply(204, "");
    const payload = await verify(input);
    if (path === "/account") return reply(201, { status: "valid" }, { location: `${base}/acct/1` });
    if (path === "/order") {
      expect(payload.identifiers.map((i: { value: string }) => i.value)).toEqual(hosts);
      return reply(201, orderBody(), { location: `${base}/order/1` });
    }
    const authMatch = /^\/authz\/(.+)$/.exec(path);
    if (authMatch) {
      const host = authMatch[1] as string;
      return reply(200, {
        status: state.auth.get(host) ?? "pending",
        identifier: { type: "dns", value: host },
        challenges: [
          { type: "http-01", url: `${base}/chall/http/${host}`, token: "x", status: "pending" },
          {
            type: "dns-01",
            url: `${base}/chall/${host}`,
            token: tokens.get(host),
            status: "pending",
          },
        ],
      });
    }
    const chMatch = /^\/chall\/([^/]+)$/.exec(path);
    if (chMatch) {
      const host = chMatch[1] as string;
      expect(txt.get(`_acme-challenge.${host}`)).toBe(
        await dnsChallengeValue(tokens.get(host) as string, await accountKeyFor()),
      );
      state.auth.set(host, "valid");
      return reply(200, { status: "valid" });
    }
    if (path === "/finalize") {
      state.csr = b64uDecode(payload.csr);
      state.order = "valid";
      return reply(200, orderBody());
    }
    if (path === "/order/1") return reply(200, orderBody());
    if (path === "/cert") return reply(200, CERT);
    return reply(404, { detail: "unknown" });
  };
  const orderBody = () => ({
    status: state.order,
    authorizations: hosts.map((h) => `${base}/authz/${h}`),
    finalize: `${base}/finalize`,
    ...(state.order === "valid" ? { certificate: `${base}/cert` } : {}),
  });
  let accountKeyFor: () => Promise<CryptoKey> = async () => {
    throw new Error("no account");
  };
  const dns = {
    async upsert(r: { name: string; content: string }) {
      txt.set(r.name, r.content);
      return { ok: true };
    },
    async remove(r: { name: string }) {
      txt.delete(r.name);
      return { ok: true };
    },
  };
  return {
    request,
    dns,
    txt,
    state,
    hosts,
    useAccount(f: () => Promise<CryptoKey>) {
      accountKeyFor = f;
    },
  };
}

describe("ACME", () => {
  test("a CSR carries the names and a valid self-signature", async () => {
    const key = await newKeyPair();
    const der = await csr(["in.acme.test", "smtp.acme.test"], key);
    const outer = tlv(der, 0);
    const info = tlv(der, outer.body);
    const algo = tlv(der, info.end);
    const sig = tlv(der, algo.end);
    const text = dec.decode(der);
    expect(text).toContain("in.acme.test");
    expect(text).toContain("smtp.acme.test");
    const ecdsa = der.subarray(sig.body + 1, sig.end);
    const seqTlv = tlv(ecdsa, 0);
    const r = tlv(ecdsa, seqTlv.body);
    const s = tlv(ecdsa, r.end);
    const fixed = (b: Uint8Array) => {
      const t = b[0] === 0 ? b.subarray(1) : b;
      const out = new Uint8Array(32);
      out.set(t, 32 - t.length);
      return out;
    };
    const raw = new Uint8Array([
      ...fixed(ecdsa.subarray(r.body, r.end)),
      ...fixed(ecdsa.subarray(s.body, s.end)),
    ]);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key.publicKey,
      raw,
      der.slice(info.start, info.end) as Uint8Array<ArrayBuffer>,
    );
    expect(ok).toBe(true);
  });

  test("an order is completed with signed requests and DNS-01 records that are removed afterwards", async () => {
    const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-acme-${crypto.randomUUID()}`;
    const fake = fakeAcme();
    fake.useAccount(async () => {
      const { accountKeyFromPkcs8 } = await import("../../src/acme/client.ts");
      return accountKeyFromPkcs8(
        Uint8Array.fromBase64((await Bun.file(`${dir}/account.key`).text()).trim()),
      );
    });
    const o = {
      directory: "https://acme.test/directory",
      email: "ops@acme.test",
      hosts: ["smtp.acme.test", "in.acme.test"],
      dir,
      dns: fake.dns,
      request: fake.request,
      log: silent,
      sleep: async () => {},
      propagationMs: 0,
      now: () => Date.parse("2026-10-19T00:00:00Z"),
    };
    expect(await ensureCertificate(o)).toBe("issued");
    expect(fake.txt.size).toBe(0);
    expect(fake.state.csr).not.toBeNull();
    expect(await Bun.file(`${dir}/cert.pem`).text()).toBe(CERT);
    expect(await Bun.file(`${dir}/key.pem`).text()).toStartWith("-----BEGIN PRIVATE KEY-----");
    const leaf = fromPem(CERT)[0] as Uint8Array;
    const state = await certificateState(
      dir,
      ["in.acme.test", "smtp.acme.test"],
      notAfter(leaf) - 40 * 86_400_000,
    );
    expect(state.due).toBe(false);
    expect((await certificateState(dir, ["other.acme.test"], 0)).due).toBe(true);
    const requests = fake.state.requests;
    expect(await ensureCertificate({ ...o, now: () => notAfter(leaf) - 40 * 86_400_000 })).toBe(
      "fresh",
    );
    expect(fake.state.requests).toBe(requests);
    await Bun.$`rm -rf ${dir}`.quiet();
  });
});
