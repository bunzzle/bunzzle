const enc = new TextEncoder();
const VERSION = 1;
const IV_BYTES = 12;

export class CryptoError extends Error {}

export async function sealWith(
  key: CryptoKey,
  plaintext: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(context) },
      key,
      plaintext as Uint8Array<ArrayBuffer>,
    ),
  );
  const out = new Uint8Array(1 + IV_BYTES + ct.length);
  out[0] = VERSION;
  out.set(iv, 1);
  out.set(ct, 1 + IV_BYTES);
  return out;
}

export async function openWith(
  key: CryptoKey,
  sealed: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  if (sealed[0] !== VERSION || sealed.length < 1 + IV_BYTES + 16) {
    throw new CryptoError("sealed data has an unknown format");
  }
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: sealed.subarray(1, 1 + IV_BYTES) as Uint8Array<ArrayBuffer>,
          additionalData: enc.encode(context),
        },
        key,
        sealed.subarray(1 + IV_BYTES) as Uint8Array<ArrayBuffer>,
      ),
    );
  } catch {
    throw new CryptoError("cannot decrypt: wrong key or tampered data");
  }
}
