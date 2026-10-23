import { fromPem } from "../asn1/der.ts";
import type { SignRaw } from "../x509/issue.ts";
import type { DkimAlgorithm, RemoteKey } from "./sign.ts";

export class KeyStoreError extends Error {}

export interface KeyStore {
  create(name: string, algorithm: DkimAlgorithm): Promise<string>;
  key(name: string): RemoteKey;
  createP256(name: string): Promise<Uint8Array>;
  signerP256(name: string): SignRaw;
}

const TIMEOUT_MS = 10_000;

export function transitStore(socket: string, mount = "transit"): KeyStore {
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    let res: Response;
    try {
      res = await fetch(`http://localhost/v1/${mount}/${path}`, {
        method,
        unix: socket,
        headers: { "X-Vault-Request": "true", "Content-Type": "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      } as RequestInit);
    } catch (err) {
      throw new KeyStoreError(`the key store is not reachable: ${(err as Error).message}`);
    }
    const text = await res.text();
    if (!res.ok) {
      const errors = (() => {
        try {
          return (JSON.parse(text) as { errors?: string[] }).errors?.join("; ");
        } catch {
          return undefined;
        }
      })();
      throw new KeyStoreError(`the key store answered ${res.status}${errors ? `: ${errors}` : ""}`);
    }
    if (text === "") return {};
    return (JSON.parse(text) as { data?: Record<string, unknown> }).data ?? {};
  };

  const createKey = async (name: string, type: string) => {
    await call("POST", `keys/${encodeURIComponent(name)}`, { type, exportable: false });
    const data = (await call("GET", `keys/${encodeURIComponent(name)}`)) as {
      type?: string;
      latest_version?: number;
      keys?: Record<string, { public_key?: string }>;
    };
    if (data.type !== type) {
      throw new KeyStoreError(`key ${name} in the store is ${data.type}, not ${type}`);
    }
    const pub = data.keys?.[String(data.latest_version ?? 1)]?.public_key;
    if (!pub) throw new KeyStoreError(`key ${name} has no public key in the store`);
    return pub;
  };

  const sign = async (name: string, input: Uint8Array, options: Record<string, string>) => {
    const data = (await call("POST", `sign/${encodeURIComponent(name)}/sha2-256`, {
      input: input.toBase64(),
      ...options,
    })) as { signature?: string };
    const sig = data.signature?.split(":").at(-1);
    if (!sig) throw new KeyStoreError(`the key store returned no signature for ${name}`);
    return sig;
  };

  return {
    async create(name, algorithm) {
      const pub = await createKey(name, algorithm === "rsa-sha256" ? "rsa-2048" : "ed25519");
      return algorithm === "rsa-sha256"
        ? pub.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "")
        : pub.trim();
    },

    async createP256(name) {
      const spki = fromPem(await createKey(name, "ecdsa-p256"))[0];
      if (!spki) throw new KeyStoreError(`key ${name} has no public key in the store`);
      return spki;
    },

    signerP256(name) {
      return async (input) =>
        Uint8Array.fromBase64(await sign(name, input, { marshaling_algorithm: "jws" }), {
          alphabet: "base64url",
        });
    },

    key(name) {
      return {
        async sign(input, algorithm) {
          const options: Record<string, string> =
            algorithm === "rsa-sha256" ? { signature_algorithm: "pkcs1v15" } : {};
          return Uint8Array.fromBase64(await sign(name, input, options));
        },
      };
    },
  };
}
