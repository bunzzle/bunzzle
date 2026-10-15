import { z } from "zod";
import type { MasterKey } from "../crypto/master.ts";
import type { DkimAlgorithm, DkimKey } from "./sign.ts";

const keyFileSchema = z.object({
  domain: z.string().min(1),
  masterKeyId: z.string().min(1).optional(),
  keys: z
    .array(
      z
        .object({
          selector: z.string().regex(/^[a-z0-9-]+(\.[a-z0-9-]+)*$/i),
          algorithm: z.enum(["rsa-sha256", "ed25519-sha256"]),
          privateKey: z.string().min(1).optional(),
          sealedPrivateKey: z.string().min(1).optional(),
          publicKey: z.string().min(1),
          state: z.enum(["active", "next", "retiring"]).optional(),
          createdAt: z.number().int().optional(),
          retiringSince: z.number().int().optional(),
        })
        .refine((k) => (k.privateKey === undefined) !== (k.sealedPrivateKey === undefined), {
          message: "each key needs exactly one of privateKey or sealedPrivateKey",
        }),
    )
    .min(1),
});

export type KeyFile = z.infer<typeof keyFileSchema>;

export interface DnsRecord {
  name: string;
  type: "TXT";
  value: string;
}

export class KeyFileError extends Error {}

function importParams(algorithm: DkimAlgorithm) {
  return algorithm === "rsa-sha256"
    ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
    : { name: "Ed25519" };
}

async function generateOne(selector: string, algorithm: DkimAlgorithm) {
  const pair = (
    algorithm === "rsa-sha256"
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
  const priv = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const pub = new Uint8Array(
    await crypto.subtle.exportKey(algorithm === "rsa-sha256" ? "spki" : "raw", pair.publicKey),
  );
  return { selector, algorithm, privateKey: priv.toBase64(), publicKey: pub.toBase64() };
}

export async function generateKeyFile(domain: string, selectorBase: string): Promise<KeyFile> {
  const d = domain.toLowerCase();
  return {
    domain: d,
    keys: [
      await generateOne(`${selectorBase}r`, "rsa-sha256"),
      await generateOne(`${selectorBase}e`, "ed25519-sha256"),
    ],
  };
}

export function dnsRecords(file: KeyFile): DnsRecord[] {
  return file.keys.map((k) => ({
    name: `${k.selector}._domainkey.${file.domain}`,
    type: "TXT",
    value: `v=DKIM1; k=${k.algorithm === "rsa-sha256" ? "rsa" : "ed25519"}; p=${k.publicKey}`,
  }));
}

export function parseKeyFile(json: unknown): KeyFile {
  const parsed = keyFileSchema.safeParse(json);
  if (!parsed.success) {
    throw new KeyFileError(
      `invalid DKIM key file: ${parsed.error.issues[0]?.message ?? "unknown"}`,
    );
  }
  return parsed.data;
}

const keyContext = (domain: string, selector: string) => `bunzzle dkim v1:${domain}:${selector}`;

export async function sealKeyFile(file: KeyFile, master: MasterKey): Promise<KeyFile> {
  const keys = [];
  for (const { privateKey, sealedPrivateKey: _, ...k } of file.keys) {
    if (privateKey === undefined) throw new KeyFileError("key file is already encrypted");
    const sealed = await master.seal(
      Uint8Array.fromBase64(privateKey),
      keyContext(file.domain, k.selector),
    );
    keys.push({ ...k, sealedPrivateKey: sealed.toBase64() });
  }
  return { domain: file.domain, masterKeyId: master.id, keys };
}

export function isEncrypted(file: KeyFile): boolean {
  return file.keys.some((k) => k.sealedPrivateKey !== undefined);
}

async function privateBytes(
  file: KeyFile,
  k: KeyFile["keys"][number],
  master: MasterKey | null,
): Promise<Uint8Array> {
  if (k.privateKey !== undefined) return Uint8Array.fromBase64(k.privateKey);
  if (!master) {
    throw new KeyFileError(
      "the DKIM key file is encrypted: set BUNZZLE_MASTER_KEY or BUNZZLE_MASTER_KEY_FILE",
    );
  }
  if (file.masterKeyId && file.masterKeyId !== master.id) {
    throw new KeyFileError("the DKIM key file was encrypted with another master key");
  }
  try {
    return await master.open(
      Uint8Array.fromBase64(k.sealedPrivateKey as string),
      keyContext(file.domain, k.selector),
    );
  } catch {
    throw new KeyFileError(`cannot decrypt DKIM key ${k.selector}: wrong master key?`);
  }
}

export async function importKeys(
  file: KeyFile,
  master: MasterKey | null = null,
): Promise<DkimKey[]> {
  const keys: DkimKey[] = [];
  for (const k of file.keys) {
    let privateKey: CryptoKey;
    const bytes = await privateBytes(file, k, master);
    try {
      privateKey = await crypto.subtle.importKey(
        "pkcs8",
        bytes as Uint8Array<ArrayBuffer>,
        importParams(k.algorithm),
        false,
        ["sign"],
      );
    } catch (err) {
      throw new KeyFileError(`cannot import key ${k.selector}: ${(err as Error).message}`);
    } finally {
      bytes.fill(0);
    }
    keys.push({ domain: file.domain, selector: k.selector, algorithm: k.algorithm, privateKey });
  }
  return keys;
}

export async function loadKeyFile(
  path: string,
  master: MasterKey | null = null,
): Promise<DkimKey[]> {
  const file = Bun.file(path);
  if (!(await file.exists())) throw new KeyFileError(`DKIM key file not found: ${path}`);
  let json: unknown;
  try {
    json = await file.json();
  } catch {
    throw new KeyFileError(`DKIM key file is not valid JSON: ${path}`);
  }
  return importKeys(parseKeyFile(json), master);
}
