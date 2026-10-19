import { bits, ecdsaSignatureDer, node, oid, pem, seq, set, utf8 } from "../asn1/der.ts";
import type { RequestInput, RequestResult } from "../net/request.ts";

export type Request = (r: RequestInput) => Promise<RequestResult>;

export interface DnsPublisher {
  upsert(record: {
    type: "TXT";
    name: string;
    content: string;
  }): Promise<{ ok: boolean; error?: string }>;
  remove(record: {
    type: "TXT";
    name: string;
    content: string;
  }): Promise<{ ok: boolean; error?: string }>;
}

export interface Issued {
  certPem: string;
  keyPem: string;
}

const enc = new TextEncoder();
const b64u = (b: Uint8Array | string) =>
  (typeof b === "string" ? enc.encode(b) : b).toBase64({
    alphabet: "base64url",
    omitPadding: true,
  });

const EC = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

export async function newKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(EC, true, ["sign", "verify"]);
}

export async function accountKeyFromPkcs8(der: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", der as Uint8Array<ArrayBuffer>, EC, true, ["sign"]);
}

export async function newAccountKey(): Promise<{ key: CryptoKey; pkcs8: Uint8Array }> {
  const pair = await newKeyPair();
  return {
    key: pair.privateKey,
    pkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

async function publicJwk(key: CryptoKey) {
  const j = await crypto.subtle.exportKey("jwk", key);
  return { crv: j.crv as string, kty: j.kty as string, x: j.x as string, y: j.y as string };
}

export async function thumbprint(key: CryptoKey): Promise<string> {
  const j = await publicJwk(key);
  const canonical = `{"crv":"${j.crv}","kty":"${j.kty}","x":"${j.x}","y":"${j.y}"}`;
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(canonical))));
}

export async function dnsChallengeValue(token: string, account: CryptoKey): Promise<string> {
  const keyAuth = `${token}.${await thumbprint(account)}`;
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(keyAuth))));
}

export async function csr(hosts: string[], key: CryptoKeyPair): Promise<Uint8Array> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
  const san = seq(...hosts.map((h) => node(0x82, enc.encode(h))));
  const extensions = seq(seq(oid("2.5.29.17"), node(0x04, san)));
  const info = seq(
    node(0x02, [0]),
    seq(set(seq(oid("2.5.4.3"), utf8(hosts[0] as string)))),
    spki,
    node(0xa0, seq(oid("1.2.840.113549.1.9.14"), set(extensions))),
  );
  const raw = new Uint8Array(await crypto.subtle.sign(SIGN, key.privateKey, Uint8Array.from(info)));
  return Uint8Array.from(seq(info, seq(oid("1.2.840.10045.4.3.2")), bits(ecdsaSignatureDer(raw))));
}

interface Directory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
}

interface Order {
  status: string;
  authorizations: string[];
  finalize: string;
  certificate?: string;
}

interface Authorization {
  status: string;
  identifier: { value: string };
  challenges: { type: string; url: string; token: string; status: string }[];
}

export class AcmeError extends Error {}

export class AcmeClient {
  #nonce: string | null = null;
  #kid: string | null = null;
  #dir: Directory | null = null;

  constructor(
    private readonly directoryUrl: string,
    private readonly account: CryptoKey,
    private readonly request: Request,
    private readonly sleep: (ms: number) => Promise<void> = Bun.sleep,
  ) {}

  async #directory(): Promise<Directory> {
    if (this.#dir) return this.#dir;
    const r = await this.request({ method: "GET", url: this.directoryUrl, maxBody: 64 * 1024 });
    if (!r.ok || r.status !== 200)
      throw new AcmeError(`ACME directory: ${r.ok ? r.status : r.error}`);
    this.#dir = JSON.parse(r.body) as Directory;
    return this.#dir;
  }

  async #freshNonce(): Promise<string> {
    if (this.#nonce) {
      const n = this.#nonce;
      this.#nonce = null;
      return n;
    }
    const r = await this.request({ method: "GET", url: (await this.#directory()).newNonce });
    const n = r.ok ? r.headers.get("replay-nonce") : undefined;
    if (!n) throw new AcmeError("ACME server gave no nonce");
    return n;
  }

  async #post(
    url: string,
    payload: unknown,
    withJwk = false,
  ): Promise<{ status: number; headers: Map<string, string>; body: string }> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const nonce = await this.#freshNonce();
      const protectedHeader = {
        alg: "ES256",
        nonce,
        url,
        ...(withJwk || !this.#kid ? { jwk: await publicJwk(this.account) } : { kid: this.#kid }),
      };
      const p = b64u(JSON.stringify(protectedHeader));
      const body = payload === "" ? "" : b64u(JSON.stringify(payload));
      const sig = new Uint8Array(
        await crypto.subtle.sign(SIGN, this.account, enc.encode(`${p}.${body}`)),
      );
      const r = await this.request({
        method: "POST",
        url,
        headers: { "Content-Type": "application/jose+json" },
        body: JSON.stringify({ protected: p, payload: body, signature: b64u(sig) }),
        maxBody: 1024 * 1024,
      });
      if (!r.ok) throw new AcmeError(`ACME request failed: ${r.error}`);
      this.#nonce = r.headers.get("replay-nonce") ?? null;
      if (r.status === 400 && r.body.includes("badNonce")) continue;
      if (r.status >= 400) {
        let detail = r.body.slice(0, 300);
        try {
          detail = (JSON.parse(r.body) as { detail?: string }).detail ?? detail;
        } catch {}
        throw new AcmeError(`ACME ${r.status}: ${detail}`);
      }
      return r;
    }
    throw new AcmeError("ACME server kept rejecting the nonce");
  }

  async register(email: string): Promise<void> {
    const dir = await this.#directory();
    const r = await this.#post(
      dir.newAccount,
      { termsOfServiceAgreed: true, contact: [`mailto:${email}`] },
      true,
    );
    this.#kid = r.headers.get("location") ?? null;
    if (!this.#kid) throw new AcmeError("ACME server gave no account URL");
  }

  async #poll<T extends { status: string }>(url: string, done: (t: T) => boolean): Promise<T> {
    for (let i = 0; i < 30; i++) {
      const t = JSON.parse((await this.#post(url, "")).body) as T;
      if (t.status === "invalid") throw new AcmeError(`ACME: ${url} became invalid`);
      if (done(t)) return t;
      await this.sleep(2_000);
    }
    throw new AcmeError(`ACME: ${url} did not finish in time`);
  }

  async issue(hosts: string[], dns: DnsPublisher, propagationMs = 30_000): Promise<Issued> {
    const dir = await this.#directory();
    const created = await this.#post(dir.newOrder, {
      identifiers: hosts.map((value) => ({ type: "dns", value })),
    });
    const orderUrl = created.headers.get("location");
    if (!orderUrl) throw new AcmeError("ACME server gave no order URL");
    const order = JSON.parse(created.body) as Order;
    const published: { type: "TXT"; name: string; content: string }[] = [];
    try {
      const pending: { url: string; challenge: string }[] = [];
      for (const authUrl of order.authorizations) {
        const auth = JSON.parse((await this.#post(authUrl, "")).body) as Authorization;
        if (auth.status === "valid") continue;
        const ch = auth.challenges.find((c) => c.type === "dns-01");
        if (!ch) throw new AcmeError(`no dns-01 challenge for ${auth.identifier.value}`);
        const record = {
          type: "TXT" as const,
          name: `_acme-challenge.${auth.identifier.value}`,
          content: await dnsChallengeValue(ch.token, this.account),
        };
        const r = await dns.upsert(record);
        if (!r.ok) throw new AcmeError(`could not publish ${record.name}: ${r.error}`);
        published.push(record);
        pending.push({ url: authUrl, challenge: ch.url });
      }
      if (pending.length) await this.sleep(propagationMs);
      for (const p of pending) {
        await this.#post(p.challenge, {});
        await this.#poll<Authorization>(p.url, (a) => a.status === "valid");
      }
      const key = await newKeyPair();
      await this.#post(order.finalize, { csr: b64u(await csr(hosts, key)) });
      const done = await this.#poll<Order>(
        orderUrl,
        (o) => o.status === "valid" && !!o.certificate,
      );
      const cert = await this.#post(done.certificate as string, "");
      const keyPem = pem(
        "PRIVATE KEY",
        new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey)),
      );
      return { certPem: cert.body, keyPem };
    } finally {
      for (const r of published) await dns.remove(r).catch(() => {});
    }
  }
}
