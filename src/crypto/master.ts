import { CryptoError, openWith, sealWith } from "./aead.ts";

const enc = new TextEncoder();

export class MasterKeyError extends CryptoError {}

export interface MasterKey {
  id: string;
  mac(data: Uint8Array, purpose: string): Promise<Uint8Array>;
  derive(purpose: string): Promise<Uint8Array>;
  seal(plaintext: Uint8Array, context: string): Promise<Uint8Array>;
  open(sealed: Uint8Array, context: string): Promise<Uint8Array>;
}

export function generateMasterKey(): string {
  return crypto.getRandomValues(new Uint8Array(32)).toBase64();
}

async function hkdf(base: CryptoKey, info: string, bits: number): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) },
      base,
      bits,
    ),
  );
}

export async function masterKeyFrom(text: string): Promise<MasterKey> {
  let raw: Uint8Array;
  try {
    raw = Uint8Array.fromBase64(text.trim());
  } catch {
    throw new MasterKeyError("the master key must be base64");
  }
  if (raw.length !== 32) {
    throw new MasterKeyError(
      `the master key must be 32 bytes, got ${raw.length} (create one with \`bunzzle master-key\`)`,
    );
  }
  const base = await crypto.subtle.importKey("raw", raw as Uint8Array<ArrayBuffer>, "HKDF", false, [
    "deriveBits",
  ]);
  const sealing = await crypto.subtle.importKey(
    "raw",
    (await hkdf(base, "bunzzle seal v1", 256)) as Uint8Array<ArrayBuffer>,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  const id = (await hkdf(base, "bunzzle key id v1", 64)).toHex();
  const macKeys = new Map<string, CryptoKey>();
  const macKey = async (purpose: string) => {
    let k = macKeys.get(purpose);
    if (!k) {
      k = await crypto.subtle.importKey(
        "raw",
        (await hkdf(base, `bunzzle mac v1:${purpose}`, 256)) as Uint8Array<ArrayBuffer>,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      macKeys.set(purpose, k);
    }
    return k;
  };
  return {
    id,
    mac: async (data, purpose) =>
      new Uint8Array(
        await crypto.subtle.sign("HMAC", await macKey(purpose), data as Uint8Array<ArrayBuffer>),
      ),
    derive: (purpose) => hkdf(base, `bunzzle derive v1:${purpose}`, 256),
    seal: (plaintext, context) => sealWith(sealing, plaintext, context),
    open: async (sealed, context) => {
      try {
        return await openWith(sealing, sealed, context);
      } catch {
        throw new MasterKeyError("cannot decrypt: wrong key or tampered data");
      }
    },
  };
}
