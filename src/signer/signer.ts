import { type Clock, systemClock } from "../core/clock.ts";
import { type EpochPublicKey, epochOf, openBody, type SealedBody } from "../crypto/envelope.ts";
import type { MasterKey } from "../crypto/master.ts";
import { splitMessage } from "../dkim/canonicalize.ts";
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
import { makeToken, readToken } from "./tokens.ts";

export class SignerError extends Error {
  constructor(
    readonly code: "no-key" | "epoch-gone" | "unreadable" | "bad-message",
    message: string,
  ) {
    super(message);
  }
}

export interface OpenOptions {
  lane?: "transactional" | "bulk";
  bounceDomain?: string | null;
}

export interface Opened {
  data: string;
  bounceToken: string;
}

export interface SignerOptions {
  publicUrl?: string | null;
  master: MasterKey;
  keystorePath: string;
  dkimKeyFiles: string[];
  dkimDir?: string;
  clock?: Clock;
}

export type KeyState = "active" | "next" | "retiring";

export interface PublicKeyInfo {
  selector: string;
  algorithm: "rsa-sha256" | "ed25519-sha256";
  publicKey: string;
  state: KeyState;
  createdAt: number | null;
  retiringSince: number | null;
}

interface DomainKeys {
  path: string;
  file: KeyFile;
  keys: Map<string, DkimKey>;
}

async function readKeyFile(path: string): Promise<KeyFile> {
  const f = Bun.file(path);
  if (!(await f.exists())) throw new KeyFileError(`DKIM key file not found: ${path}`);
  return parseKeyFile(await f.json());
}

const publicOf = (file: KeyFile): PublicKeyInfo[] =>
  file.keys.map((k) => ({
    selector: k.selector,
    algorithm: k.algorithm,
    publicKey: k.publicKey,
    state: k.state ?? "active",
    createdAt: k.createdAt ?? null,
    retiringSince: k.retiringSince ?? null,
  }));

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
  readonly #domains = new Map<string, DomainKeys>();
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
    for (const path of o.dkimKeyFiles) await signer.#add(path, await readKeyFile(path));
    return signer;
  }

  async #add(path: string, file: KeyFile) {
    const imported = await importKeys(file, this.#o.master);
    const existing = this.#domains.get(file.domain);
    const keys = new Map(existing?.keys ?? []);
    for (const k of imported) keys.set(k.selector, k);
    const merged: KeyFile = existing
      ? {
          ...file,
          keys: [
            ...existing.file.keys.filter((k) => !file.keys.some((x) => x.selector === k.selector)),
            ...file.keys,
          ],
        }
      : file;
    const dir = this.#o.dkimDir;
    const canonical = dir && path.startsWith(`${dir}/`) ? path : (existing?.path ?? path);
    this.#domains.set(file.domain, { path: canonical, file: merged, keys });
  }

  #active(domain: string): DkimKey[] {
    const d = this.#domains.get(domain);
    if (!d) return [];
    return d.file.keys
      .filter((k) => (k.state ?? "active") === "active")
      .flatMap((k) => {
        const key = d.keys.get(k.selector);
        return key ? [key] : [];
      });
  }

  publicKeys(domain: string): PublicKeyInfo[] | null {
    const d = this.#domains.get(domain);
    return d ? publicOf(d.file) : null;
  }

  ensureKeys(domain: string, selectorBase: string): Promise<PublicKeyInfo[]> {
    const existing = this.publicKeys(domain);
    if (existing) return Promise.resolve(existing);
    let creating = this.#creating.get(domain);
    if (!creating) {
      creating = this.#generate(domain, selectorBase).finally(() => this.#creating.delete(domain));
      this.#creating.set(domain, creating);
    }
    return creating;
  }

  async #write(path: string, file: KeyFile, replace: boolean) {
    const dir = this.#o.dkimDir;
    if (!dir) throw new KeyFileError("this signer has no directory for DKIM keys");
    const tmp = `${path}.${crypto.randomUUID()}.tmp`;
    await Bun.$`mkdir -p ${dir} && chmod 700 ${dir}`.quiet();
    await Bun.write(tmp, `${JSON.stringify(file, null, 2)}\n`);
    if (replace) await Bun.$`chmod 600 ${tmp} && mv -f ${tmp} ${path}`.quiet();
    else await Bun.$`chmod 600 ${tmp} && mv -n ${tmp} ${path} ; rm -f ${tmp}`.quiet();
  }

  async #generate(domain: string, selectorBase: string): Promise<PublicKeyInfo[]> {
    const dir = this.#o.dkimDir;
    if (!dir) throw new KeyFileError("this signer has no directory for new DKIM keys");
    const fresh = await generateKeyFile(domain, selectorBase);
    const now = this.#clock.now();
    const file = await sealKeyFile(
      {
        ...fresh,
        keys: fresh.keys.map((k) => ({ ...k, state: "active" as const, createdAt: now })),
      },
      this.#o.master,
    );
    const path = `${dir}/${file.domain}.json`;
    await this.#write(path, file, false);
    await this.#add(path, await readKeyFile(path));
    return this.publicKeys(domain) ?? [];
  }

  #rotatable(domain: string): DomainKeys {
    const d = this.#domains.get(domain);
    if (!d) throw new SignerError("no-key", `no DKIM key for ${domain}`);
    const dir = this.#o.dkimDir;
    if (!dir || !d.path.startsWith(`${dir}/`)) {
      throw new KeyFileError(
        `the DKIM keys of ${domain} live outside ${dir ?? "the keys directory"}; move the file there to enable rotation`,
      );
    }
    return d;
  }

  async #save(domain: string, file: KeyFile) {
    const d = this.#rotatable(domain);
    await this.#write(d.path, file, true);
    const keys = new Map<string, DkimKey>();
    for (const k of await importKeys(file, this.#o.master)) keys.set(k.selector, k);
    this.#domains.set(domain, { path: d.path, file, keys });
  }

  async rotateStart(domain: string, selectorBase: string): Promise<PublicKeyInfo[]> {
    const d = this.#rotatable(domain);
    if (d.file.keys.some((k) => k.state === "next")) return publicOf(d.file);
    if (d.file.keys.some((k) => k.selector.startsWith(selectorBase))) {
      throw new KeyFileError(`selector ${selectorBase} is already used for ${domain}`);
    }
    const fresh = await generateKeyFile(domain, selectorBase);
    const now = this.#clock.now();
    const sealed = await sealKeyFile(
      { ...fresh, keys: fresh.keys.map((k) => ({ ...k, state: "next" as const, createdAt: now })) },
      this.#o.master,
    );
    await this.#save(domain, { ...d.file, keys: [...d.file.keys, ...sealed.keys] });
    return this.publicKeys(domain) ?? [];
  }

  async promote(domain: string): Promise<PublicKeyInfo[]> {
    const d = this.#rotatable(domain);
    if (!d.file.keys.some((k) => k.state === "next")) {
      throw new KeyFileError(`no new DKIM keys waiting for ${domain}`);
    }
    const now = this.#clock.now();
    const keys = d.file.keys.map((k) => {
      const state = k.state ?? "active";
      if (state === "next") return { ...k, state: "active" as const };
      if (state === "active") return { ...k, state: "retiring" as const, retiringSince: now };
      return k;
    });
    await this.#save(domain, { ...d.file, keys });
    return this.publicKeys(domain) ?? [];
  }

  async dropRetiring(domain: string): Promise<PublicKeyInfo[]> {
    const d = this.#rotatable(domain);
    const gone = d.file.keys.filter((k) => k.state === "retiring").map((k) => k.selector);
    if (gone.length === 0) return [];
    const before = publicOf(d.file).filter((k) => gone.includes(k.selector));
    await this.#save(domain, {
      ...d.file,
      keys: d.file.keys.filter((k) => k.state !== "retiring"),
    });
    return before;
  }

  async signCanary(domain: string, which: "active" | "next"): Promise<string> {
    const d = this.#domains.get(domain);
    if (!d) throw new SignerError("no-key", `no DKIM key for ${domain}`);
    const keys = d.file.keys
      .filter((k) => (k.state ?? "active") === which)
      .flatMap((k) => {
        const key = d.keys.get(k.selector);
        return key ? [key] : [];
      });
    if (keys.length === 0) throw new SignerError("no-key", `no ${which} DKIM keys for ${domain}`);
    const now = new Date(this.#clock.now());
    const raw = [
      `From: dkim-check@${domain}`,
      `To: dkim-check@${domain}`,
      "Subject: Bunzzle DKIM self-check",
      `Date: ${now.toUTCString()}`,
      `Message-ID: <${crypto.randomUUID()}@${domain}>`,
      "",
      "self-check",
      "",
    ].join("\r\n");
    return signMessage(raw, keys, now);
  }

  domains(): string[] {
    return [...this.#domains.keys()].filter((d) => this.#active(d).length > 0).sort();
  }

  async epochKey(): Promise<EpochPublicKey> {
    const pair = await this.#keystore.current(this.#clock.now());
    return { epoch: pair.epoch, publicKey: pair.publicKey };
  }

  async open(messageId: string, body: SealedBody, o: OpenOptions = {}): Promise<Opened> {
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
    const keys = this.#active(domain);
    if (keys.length === 0) throw new SignerError("no-key", `no DKIM key for ${domain}`);
    const master = this.#o.master;
    const bounceToken = await makeToken(master, "b", messageId);
    const lane = o.lane ?? "transactional";
    const extra = [`X-Bunzzle-Ref: ${bounceToken}`, `Feedback-ID: ${lane}:${domain}:bunzzle`];
    const hasUnsubscribe = splitMessage(raw).headers.some(
      (h) => h.name.trim().toLowerCase() === "list-unsubscribe",
    );
    if (lane === "bulk" && !hasUnsubscribe) {
      const token = await makeToken(master, "u", messageId);
      const links: string[] = [];
      const base = this.#o.publicUrl?.replace(/\/+$/, "");
      if (base) links.push(`<${base}/u/${token}>`);
      if (o.bounceDomain) links.push(`<mailto:u-${token}@${o.bounceDomain}>`);
      if (links.length > 0) extra.push(`List-Unsubscribe: ${links.join(", ")}`);
      if (base) extra.push("List-Unsubscribe-Post: List-Unsubscribe=One-Click");
    }
    const data = await signMessage(
      `${extra.join("\r\n")}\r\n${raw}`,
      keys,
      new Date(this.#clock.now()),
    );
    return { data, bounceToken };
  }

  readToken(token: string) {
    return readToken(this.#o.master, token);
  }

  async webhookSecret(id: string): Promise<string> {
    return `whsec_${(await this.#o.master.derive(`webhook:${id}`)).toBase64()}`;
  }

  async signWebhook(id: string, msgId: string, timestamp: number, body: string): Promise<string> {
    return this.#sign(`webhook:${id}`, msgId, timestamp, body);
  }

  async routeSecret(id: string): Promise<string> {
    return `whsec_${(await this.#o.master.derive(`route:${id}`)).toBase64()}`;
  }

  async openInbound(
    id: string,
    body: SealedBody,
    routeId: string,
    msgId: string,
    timestamp: number,
  ): Promise<{ body: string; signature: string }> {
    const pair = await this.#keystore.get(body.epoch);
    if (!pair) {
      throw new SignerError(
        "epoch-gone",
        `the key for day ${body.epoch} was destroyed (retention)`,
      );
    }
    let payload: string;
    try {
      payload = await openBody(pair, id, body);
    } catch {
      throw new SignerError("unreadable", "the body cannot be decrypted with its key");
    }
    return {
      body: payload,
      signature: await this.#sign(`route:${routeId}`, msgId, timestamp, payload),
    };
  }

  async #sign(purpose: string, msgId: string, timestamp: number, body: string): Promise<string> {
    const key = await crypto.subtle.importKey(
      "raw",
      (await this.#o.master.derive(purpose)) as Uint8Array<ArrayBuffer>,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const mac = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(`${msgId}.${timestamp}.${body}`),
    );
    return `v1,${new Uint8Array(mac).toBase64()}`;
  }

  async shred(retentionDays: number): Promise<number[]> {
    return this.#keystore.shred(epochOf(this.#clock.now()) - retentionDays);
  }
}
