import { CryptoError, openWith, sealWith } from "./aead.ts";

const enc = new TextEncoder();
const dec = new TextDecoder();
const PKCS8_X25519 = Uint8Array.fromHex("302e020100300506032b656e04220420");
const PUB = 32;

export interface EpochPublicKey {
  epoch: number;
  publicKey: Uint8Array;
}

export interface EpochKeyPair extends EpochPublicKey {
  privateKey: CryptoKey;
}

export interface SealedBody {
  epoch: number;
  wrapped: Uint8Array;
  body: Uint8Array;
}

export function epochOf(time: number): number {
  return Math.floor(time / 86_400_000);
}

export function newEpochSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function epochKeyPair(epoch: number, seed: Uint8Array): Promise<EpochKeyPair> {
  const pkcs8 = new Uint8Array(PKCS8_X25519.length + seed.length);
  pkcs8.set(PKCS8_X25519);
  pkcs8.set(seed, PKCS8_X25519.length);
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, [
    "deriveBits",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicKey = Uint8Array.fromBase64(jwk.x as string, { alphabet: "base64url" });
  return { epoch, publicKey, privateKey };
}

async function x25519Public(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw as Uint8Array<ArrayBuffer>,
    { name: "X25519" },
    true,
    [],
  );
}

async function kek(
  shared: Uint8Array,
  eph: Uint8Array,
  recipient: Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    "raw",
    shared as Uint8Array<ArrayBuffer>,
    "HKDF",
    false,
    ["deriveKey"],
  );
  const salt = new Uint8Array(PUB * 2);
  salt.set(eph);
  salt.set(recipient, PUB);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

const keyInfo = (epoch: number, messageId: string) => `bunzzle body key v1:${epoch}:${messageId}`;
const bodyContext = (messageId: string) => `bunzzle body v1:${messageId}`;

export async function sealBody(
  to: EpochPublicKey,
  messageId: string,
  plaintext: string,
): Promise<SealedBody> {
  const dekBytes = crypto.getRandomValues(new Uint8Array(32));
  const dek = await crypto.subtle.importKey("raw", dekBytes, { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const body = await sealWith(dek, enc.encode(plaintext), bodyContext(messageId));
  const eph = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ])) as unknown as CryptoKeyPair;
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: await x25519Public(to.publicKey) },
      eph.privateKey,
      256,
    ),
  );
  const k = await kek(shared, ephRaw, to.publicKey, keyInfo(to.epoch, messageId));
  const sealedKey = await sealWith(k, dekBytes, keyInfo(to.epoch, messageId));
  dekBytes.fill(0);
  const wrapped = new Uint8Array(PUB + sealedKey.length);
  wrapped.set(ephRaw);
  wrapped.set(sealedKey, PUB);
  return { epoch: to.epoch, wrapped, body };
}

interface Ephemeral {
  epoch: number;
  recipient: Uint8Array;
  raw: Uint8Array;
  base: CryptoKey;
  until: number;
}

export class BodySealer {
  readonly #reuseMs: number;
  readonly #now: () => number;
  #current: Promise<Ephemeral> | null = null;

  constructor({ reuseMs = 1_000, now = Date.now }: { reuseMs?: number; now?: () => number } = {}) {
    this.#reuseMs = reuseMs;
    this.#now = now;
  }

  async seal(to: EpochPublicKey, messageId: string, plaintext: string): Promise<SealedBody> {
    const e = await this.#ephemeral(to);
    const dekBytes = crypto.getRandomValues(new Uint8Array(32));
    const dek = await crypto.subtle.importKey("raw", dekBytes, { name: "AES-GCM" }, false, [
      "encrypt",
    ]);
    const body = await sealWith(dek, enc.encode(plaintext), bodyContext(messageId));
    const salt = new Uint8Array(PUB * 2);
    salt.set(e.raw);
    salt.set(e.recipient, PUB);
    const k = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(keyInfo(e.epoch, messageId)) },
      e.base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const sealedKey = await sealWith(k, dekBytes, keyInfo(e.epoch, messageId));
    dekBytes.fill(0);
    const wrapped = new Uint8Array(PUB + sealedKey.length);
    wrapped.set(e.raw);
    wrapped.set(sealedKey, PUB);
    return { epoch: e.epoch, wrapped, body };
  }

  async #ephemeral(to: EpochPublicKey): Promise<Ephemeral> {
    const pending = this.#current;
    const current = pending ? await pending.catch(() => null) : null;
    const same =
      current !== null &&
      current.epoch === to.epoch &&
      current.until > this.#now() &&
      current.recipient.length === to.publicKey.length &&
      current.recipient.every((b, i) => b === to.publicKey[i]);
    if (same) return current;
    if (this.#current !== pending) return this.#ephemeral(to);
    const next = this.#fresh(to);
    this.#current = next;
    next.catch(() => {
      if (this.#current === next) this.#current = null;
    });
    return next;
  }

  async #fresh(to: EpochPublicKey): Promise<Ephemeral> {
    const eph = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
      "deriveBits",
    ])) as unknown as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
    const shared = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "X25519", public: await x25519Public(to.publicKey) },
        eph.privateKey,
        256,
      ),
    );
    const base = await crypto.subtle.importKey(
      "raw",
      shared as Uint8Array<ArrayBuffer>,
      "HKDF",
      false,
      ["deriveKey"],
    );
    shared.fill(0);
    return {
      epoch: to.epoch,
      recipient: new Uint8Array(to.publicKey),
      raw,
      base,
      until: this.#now() + this.#reuseMs,
    };
  }
}

export async function openBody(
  key: EpochKeyPair,
  messageId: string,
  sealed: SealedBody,
): Promise<string> {
  if (sealed.epoch !== key.epoch) throw new CryptoError("body belongs to another epoch");
  const ephRaw = sealed.wrapped.subarray(0, PUB);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: await x25519Public(ephRaw) },
      key.privateKey,
      256,
    ),
  );
  const k = await kek(shared, ephRaw, key.publicKey, keyInfo(sealed.epoch, messageId));
  const dekBytes = await openWith(
    k,
    sealed.wrapped.subarray(PUB),
    keyInfo(sealed.epoch, messageId),
  );
  const dek = await crypto.subtle.importKey(
    "raw",
    dekBytes as Uint8Array<ArrayBuffer>,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  dekBytes.fill(0);
  return dec.decode(await openWith(dek, sealed.body, bodyContext(messageId)));
}
