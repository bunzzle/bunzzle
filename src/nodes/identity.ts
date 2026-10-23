import { fromPem, pem } from "../asn1/der.ts";
import { writePrivateJson } from "../core/private-file.ts";
import { pinOf, type RpcClient } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import { certificateRequest } from "../x509/issue.ts";

const CORE_DAYS = 7;
const issued = b.object({ cert: b.string(), ca: b.string() });
const saved = b.object({ cert: b.string(), key: b.string(), ca: b.string() });

export interface Identity {
  cert: string;
  key: string;
  ca: string;
  pin: string;
  notAfter: number;
}

async function newKey() {
  return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

function identityOf(cert: string, key: string, ca: string): Identity {
  const parsed = parseCertificate(fromPem(cert)[0] as Uint8Array);
  return { cert, key, ca, pin: pinOf(parsed.spki), notAfter: parsed.notAfter };
}

export class CoreIdentity {
  readonly #dir: string;
  readonly #signer: RpcClient;
  #current: Identity;

  private constructor(dir: string, signer: RpcClient, current: Identity) {
    this.#dir = dir;
    this.#signer = signer;
    this.#current = current;
  }

  static async load(dir: string, signer: RpcClient, now: number): Promise<CoreIdentity> {
    await Bun.$`mkdir -p ${dir} && chmod 700 ${dir}`.quiet();
    const file = Bun.file(`${dir}/core.json`);
    if (await file.exists()) {
      const parsed = saved.safeParse(await file.json());
      if (parsed.success) {
        const { cert, key, ca } = parsed.data;
        const current = identityOf(cert, key, ca);
        if (current.notAfter > now) return new CoreIdentity(dir, signer, current);
      }
    }
    const id = new CoreIdentity(dir, signer, await CoreIdentity.#issue(signer));
    await id.#save();
    return id;
  }

  static async #issue(signer: RpcClient): Promise<Identity> {
    const key = await newKey();
    const csr = await certificateRequest("core", key);
    const { cert, ca } = await signer.call(
      "issueNodeCertificate",
      { csr: csr.toBase64(), purpose: "client", days: CORE_DAYS },
      { result: issued },
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
    const identity = identityOf(cert, pem("PRIVATE KEY", pkcs8), ca);
    pkcs8.fill(0);
    return identity;
  }

  #save(): Promise<void> {
    const { cert, key, ca } = this.#current;
    return writePrivateJson(`${this.#dir}/core.json`, { cert, key, ca });
  }

  current(): Identity {
    return this.#current;
  }

  async renew(beforeSwitch: (next: Identity) => Promise<void>): Promise<Identity> {
    const next = await CoreIdentity.#issue(this.#signer);
    await beforeSwitch(next);
    this.#current = next;
    await this.#save();
    return next;
  }
}
