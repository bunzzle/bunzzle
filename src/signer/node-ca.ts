import { pem } from "../asn1/der.ts";
import { writePrivateJson } from "../core/private-file.ts";
import { type MasterKey, MasterKeyError } from "../crypto/master.ts";
import type { KeyStore } from "../dkim/store.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import {
  distinguishedName,
  issueCertificate,
  type Purpose,
  type SignRaw,
  signWith,
} from "../x509/issue.ts";

const DAY = 86_400_000;
const CA_DAYS = 730;
const SKEW_MS = 5 * 60_000;

const schema = b.object({
  version: b.literal(1),
  masterKeyId: b.string().min(1),
  cas: b.array(
    b.object({
      name: b.string().regex(/^bunzzle-node-ca-[0-9a-f]{8}$/),
      cert: b.string().min(1),
      sealedKey: b.string().min(1).optional(),
      storeKey: b.string().min(1).optional(),
    }),
  ),
});

type CaFile = b.infer<typeof schema>;
type CaEntry = CaFile["cas"][number];

interface Ca {
  name: string;
  der: Uint8Array;
  notAfter: number;
  sign: SignRaw;
}

const context = (name: string) => `bunzzle node ca v1:${name}`;

export class NodeCa {
  readonly #path: string;
  readonly #master: MasterKey;
  readonly #store: KeyStore | null;
  #file: CaFile;
  #cas: Ca[] = [];

  private constructor(path: string, master: MasterKey, store: KeyStore | null, file: CaFile) {
    this.#path = path;
    this.#master = master;
    this.#store = store;
    this.#file = file;
  }

  static async open(
    path: string,
    master: MasterKey,
    store: KeyStore | null,
    now: number,
  ): Promise<NodeCa> {
    const f = Bun.file(path);
    if (!(await f.exists())) {
      const ca = new NodeCa(path, master, store, { version: 1, masterKeyId: master.id, cas: [] });
      await ca.#add(await ca.#create(now));
      return ca;
    }
    const parsed = schema.safeParse(await f.json());
    if (!parsed.success) throw new MasterKeyError(`node CA file ${path} is not valid`);
    if (parsed.data.masterKeyId !== master.id) {
      throw new MasterKeyError(`node CA file ${path} was created with another master key`);
    }
    const ca = new NodeCa(path, master, store, parsed.data);
    ca.#cas = await Promise.all(parsed.data.cas.map((e) => ca.#load(e)));
    return ca;
  }

  async #create(now: number): Promise<CaEntry> {
    const name = `bunzzle-node-ca-${crypto.getRandomValues(new Uint8Array(4)).toHex()}`;
    let spki: Uint8Array;
    let sign: SignRaw;
    let entry: Omit<CaEntry, "cert">;
    if (this.#store) {
      spki = await this.#store.createP256(name);
      sign = this.#store.signerP256(name);
      entry = { name, storeKey: name };
    } else {
      const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ])) as CryptoKeyPair;
      spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
      const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
      const sealed = await this.#master.seal(pkcs8, context(name));
      pkcs8.fill(0);
      sign = signWith(pair.privateKey);
      entry = { name, sealedKey: sealed.toBase64() };
    }
    const der = await issueCertificate({
      name,
      spki,
      purpose: "ca",
      issuer: distinguishedName(name),
      sign,
      notBefore: now - SKEW_MS,
      notAfter: now + CA_DAYS * DAY,
    });
    return { ...entry, cert: der.toBase64() };
  }

  async #load(e: CaEntry): Promise<Ca> {
    const der = Uint8Array.fromBase64(e.cert);
    const { notAfter } = parseCertificate(der);
    if (e.storeKey) {
      if (!this.#store) throw new MasterKeyError(`node CA ${e.name} is in the key store`);
      return { name: e.name, der, notAfter, sign: this.#store.signerP256(e.storeKey) };
    }
    if (!e.sealedKey) throw new MasterKeyError(`node CA ${e.name} has no key`);
    const pkcs8 = await this.#master.open(Uint8Array.fromBase64(e.sealedKey), context(e.name));
    const key = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8 as Uint8Array<ArrayBuffer>,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    pkcs8.fill(0);
    return { name: e.name, der, notAfter, sign: signWith(key) };
  }

  async #add(entry: CaEntry): Promise<void> {
    const ca = await this.#load(entry);
    this.#file = { ...this.#file, cas: [...this.#file.cas, entry] };
    await writePrivateJson(this.#path, this.#file);
    this.#cas.push(ca);
  }

  #current(): Ca {
    const ca = this.#cas.at(-1);
    if (!ca) throw new MasterKeyError("no node CA");
    return ca;
  }

  trusted(): string {
    return this.#cas.map((ca) => pem("CERTIFICATE", ca.der)).join("");
  }

  expiries(): { name: string; notAfter: number }[] {
    return this.#cas.map(({ name, notAfter }) => ({ name, notAfter }));
  }

  async issue(
    name: string,
    spki: Uint8Array,
    purpose: Exclude<Purpose, "ca">,
    days: number,
    now: number,
  ): Promise<string> {
    const ca = this.#current();
    const der = await issueCertificate({
      name,
      spki,
      purpose,
      issuer: distinguishedName(ca.name),
      sign: ca.sign,
      notBefore: now - SKEW_MS,
      notAfter: Math.min(now + days * DAY, ca.notAfter),
    });
    return pem("CERTIFICATE", der);
  }
}
