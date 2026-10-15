import { type Clock, systemClock } from "../core/clock.ts";
import { type EpochPublicKey, epochOf, openBody, type SealedBody } from "../crypto/envelope.ts";
import type { MasterKey } from "../crypto/master.ts";
import {
  generateKeyFile,
  importKeys,
  type KeyFile,
  KeyFileError,
  parseKeyFile,
  sealKeyFile,
} from "../dkim/keys.ts";
import { type DkimKey, signMessage } from "../dkim/sign.ts";
import { AddressError } from "../mime/address.ts";
import { senderDomainOf } from "../mime/from.ts";
import { Keystore } from "./keystore.ts";

export class SignerError extends Error {
  constructor(
    readonly code: "no-key" | "epoch-gone" | "unreadable" | "bad-message",
    message: string,
  ) {
    super(message);
  }
}

export interface SignerOptions {
  master: MasterKey;
  keystorePath: string;
  dkimKeyFiles: string[];
  dkimDir?: string;
  clock?: Clock;
}

export interface PublicKeyInfo {
  selector: string;
  algorithm: "rsa-sha256" | "ed25519-sha256";
  publicKey: string;
}

async function readKeyFile(path: string): Promise<KeyFile> {
  const f = Bun.file(path);
  if (!(await f.exists())) throw new KeyFileError(`DKIM key file not found: ${path}`);
  return parseKeyFile(await f.json());
}

const publicOf = (file: KeyFile): PublicKeyInfo[] =>
  file.keys.map((k) => ({ selector: k.selector, algorithm: k.algorithm, publicKey: k.publicKey }));

export async function dkimKeyFilesIn(dir: string): Promise<string[]> {
  if (!(await dirExists(dir))) return [];
  const files: string[] = [];
  for await (const f of new Bun.Glob("*.json").scan({ cwd: dir })) files.push(`${dir}/${f}`);
  return files.sort();
}

async function dirExists(dir: string): Promise<boolean> {
  return (await Bun.$`test -d ${dir}`.nothrow().quiet()).exitCode === 0;
}

export class Signer {
  readonly #keystore: Keystore;
  readonly #keys = new Map<string, DkimKey[]>();
  readonly #public = new Map<string, PublicKeyInfo[]>();
  readonly #creating = new Map<string, Promise<PublicKeyInfo[]>>();
  readonly #o: SignerOptions;
  readonly #clock: Clock;

  private constructor(keystore: Keystore, o: SignerOptions) {
    this.#keystore = keystore;
    this.#o = o;
    this.#clock = o.clock ?? systemClock;
  }

  static async create(o: SignerOptions): Promise<Signer> {
    const keystore = await Keystore.open(o.keystorePath, o.master);
    const signer = new Signer(keystore, o);
    for (const path of o.dkimKeyFiles) await signer.#add(await readKeyFile(path));
    return signer;
  }

  async #add(file: KeyFile) {
    const keys = await importKeys(file, this.#o.master);
    this.#keys.set(file.domain, [...(this.#keys.get(file.domain) ?? []), ...keys]);
    this.#public.set(file.domain, [...(this.#public.get(file.domain) ?? []), ...publicOf(file)]);
  }

  publicKeys(domain: string): PublicKeyInfo[] | null {
    return this.#public.get(domain) ?? null;
  }

  ensureKeys(domain: string, selectorBase: string): Promise<PublicKeyInfo[]> {
    const existing = this.#public.get(domain);
    if (existing) return Promise.resolve(existing);
    let creating = this.#creating.get(domain);
    if (!creating) {
      creating = this.#generate(domain, selectorBase).finally(() => this.#creating.delete(domain));
      this.#creating.set(domain, creating);
    }
    return creating;
  }

  async #generate(domain: string, selectorBase: string): Promise<PublicKeyInfo[]> {
    const dir = this.#o.dkimDir;
    if (!dir) throw new KeyFileError("this signer has no directory for new DKIM keys");
    const file = await sealKeyFile(await generateKeyFile(domain, selectorBase), this.#o.master);
    const path = `${dir}/${file.domain}.json`;
    const tmp = `${path}.${crypto.randomUUID()}.tmp`;
    await Bun.$`mkdir -p ${dir} && chmod 700 ${dir}`.quiet();
    await Bun.write(tmp, `${JSON.stringify(file, null, 2)}\n`);
    await Bun.$`chmod 600 ${tmp} && mv -n ${tmp} ${path}`.quiet();
    await Bun.$`rm -f ${tmp}`.quiet();
    await this.#add(await readKeyFile(path));
    return this.#public.get(domain) ?? [];
  }

  domains(): string[] {
    return [...this.#keys.keys()].sort();
  }

  async epochKey(): Promise<EpochPublicKey> {
    const pair = await this.#keystore.current(this.#clock.now());
    return { epoch: pair.epoch, publicKey: pair.publicKey };
  }

  async open(messageId: string, body: SealedBody): Promise<string> {
    const pair = await this.#keystore.get(body.epoch);
    if (!pair) {
      throw new SignerError(
        "epoch-gone",
        `the key for day ${body.epoch} was destroyed (retention)`,
      );
    }
    let raw: string;
    try {
      raw = await openBody(pair, messageId, body);
    } catch {
      throw new SignerError("unreadable", "the body cannot be decrypted with its key");
    }
    let domain: string;
    try {
      domain = senderDomainOf(raw);
    } catch (err) {
      if (err instanceof AddressError) throw new SignerError("bad-message", err.message);
      throw err;
    }
    const keys = this.#keys.get(domain);
    if (!keys) throw new SignerError("no-key", `no DKIM key for ${domain}`);
    return signMessage(raw, keys, new Date(this.#clock.now()));
  }

  async shred(retentionDays: number): Promise<number[]> {
    return this.#keystore.shred(epochOf(this.#clock.now()) - retentionDays);
  }
}
