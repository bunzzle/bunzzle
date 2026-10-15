import { type Clock, systemClock } from "../core/clock.ts";
import { type EpochPublicKey, epochOf, openBody, type SealedBody } from "../crypto/envelope.ts";
import type { MasterKey } from "../crypto/master.ts";
import { loadKeyFile } from "../dkim/keys.ts";
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
  clock?: Clock;
}

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
  readonly #keys: Map<string, DkimKey[]>;
  readonly #clock: Clock;

  private constructor(keystore: Keystore, keys: Map<string, DkimKey[]>, clock: Clock) {
    this.#keystore = keystore;
    this.#keys = keys;
    this.#clock = clock;
  }

  static async create(o: SignerOptions): Promise<Signer> {
    const keys = new Map<string, DkimKey[]>();
    for (const path of o.dkimKeyFiles) {
      for (const k of await loadKeyFile(path, o.master)) {
        keys.set(k.domain, [...(keys.get(k.domain) ?? []), k]);
      }
    }
    const keystore = await Keystore.open(o.keystorePath, o.master);
    return new Signer(keystore, keys, o.clock ?? systemClock);
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
