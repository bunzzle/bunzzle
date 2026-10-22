import type { DkimAlgorithm, RemoteKey } from "./sign.ts";

export class KeyStoreError extends Error {}

export interface KeyStore {
  create(name: string, algorithm: DkimAlgorithm): Promise<string>;
  key(name: string): RemoteKey;
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

  return {
    async create(name, algorithm) {
      await call("POST", `keys/${encodeURIComponent(name)}`, {
        type: algorithm === "rsa-sha256" ? "rsa-2048" : "ed25519",
        exportable: false,
      });
      const data = (await call("GET", `keys/${encodeURIComponent(name)}`)) as {
        type?: string;
        latest_version?: number;
        keys?: Record<string, { public_key?: string }>;
      };
      const want = algorithm === "rsa-sha256" ? "rsa-2048" : "ed25519";
      if (data.type !== want) {
        throw new KeyStoreError(`key ${name} in the store is ${data.type}, not ${want}`);
      }
      const pub = data.keys?.[String(data.latest_version ?? 1)]?.public_key;
      if (!pub) throw new KeyStoreError(`key ${name} has no public key in the store`);
      return algorithm === "rsa-sha256"
        ? pub.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "")
        : pub.trim();
    },

    key(name) {
      return {
        async sign(input, algorithm) {
          const data = (await call("POST", `sign/${encodeURIComponent(name)}/sha2-256`, {
            input: input.toBase64(),
            ...(algorithm === "rsa-sha256" ? { signature_algorithm: "pkcs1v15" } : {}),
          })) as { signature?: string };
          const sig = data.signature?.split(":").at(-1);
          if (!sig) throw new KeyStoreError(`the key store returned no signature for ${name}`);
          return Uint8Array.fromBase64(sig);
        },
      };
    },
  };
}
