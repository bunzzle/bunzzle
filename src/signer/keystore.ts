import { z } from "zod";
import { type EpochKeyPair, epochKeyPair, epochOf, newEpochSeed } from "../crypto/envelope.ts";
import { type MasterKey, MasterKeyError } from "../crypto/master.ts";

const schema = z.object({
  version: z.literal(1),
  masterKeyId: z.string().min(1),
  epochs: z.record(z.string().regex(/^\d+$/), z.string().min(1)),
});

type StoreFile = z.infer<typeof schema>;

const context = (epoch: number) => `bunzzle epoch v1:${epoch}`;

export class Keystore {
  readonly #path: string;
  readonly #master: MasterKey;
  #file: StoreFile;
  readonly #pairs = new Map<number, EpochKeyPair>();
  readonly #creating = new Map<number, Promise<EpochKeyPair>>();
  #writing: Promise<void> = Promise.resolve();

  private constructor(path: string, master: MasterKey, file: StoreFile) {
    this.#path = path;
    this.#master = master;
    this.#file = file;
  }

  static async open(path: string, master: MasterKey): Promise<Keystore> {
    const f = Bun.file(path);
    if (!(await f.exists())) {
      const store = new Keystore(path, master, { version: 1, masterKeyId: master.id, epochs: {} });
      await store.#persist();
      return store;
    }
    const parsed = schema.safeParse(await f.json());
    if (!parsed.success) throw new MasterKeyError(`keystore ${path} is not valid`);
    if (parsed.data.masterKeyId !== master.id) {
      throw new MasterKeyError(`keystore ${path} was created with another master key`);
    }
    return new Keystore(path, master, parsed.data);
  }

  epochs(): number[] {
    return Object.keys(this.#file.epochs)
      .map(Number)
      .sort((a, b) => a - b);
  }

  async current(now: number): Promise<EpochKeyPair> {
    const epoch = epochOf(now);
    const existing = await this.get(epoch);
    if (existing) return existing;
    let creating = this.#creating.get(epoch);
    if (!creating) {
      creating = this.#create(epoch).finally(() => this.#creating.delete(epoch));
      this.#creating.set(epoch, creating);
    }
    return creating;
  }

  async #create(epoch: number): Promise<EpochKeyPair> {
    const existing = await this.get(epoch);
    if (existing) return existing;
    const seed = newEpochSeed();
    const sealed = await this.#master.seal(seed, context(epoch));
    this.#file = {
      ...this.#file,
      epochs: { ...this.#file.epochs, [epoch]: sealed.toBase64() },
    };
    await this.#persist();
    const pair = await epochKeyPair(epoch, seed);
    seed.fill(0);
    this.#pairs.set(epoch, pair);
    return pair;
  }

  async get(epoch: number): Promise<EpochKeyPair | null> {
    const cached = this.#pairs.get(epoch);
    if (cached) return cached;
    const sealed = this.#file.epochs[String(epoch)];
    if (!sealed) return null;
    const seed = await this.#master.open(Uint8Array.fromBase64(sealed), context(epoch));
    const pair = await epochKeyPair(epoch, seed);
    seed.fill(0);
    this.#pairs.set(epoch, pair);
    return pair;
  }

  async shred(beforeEpoch: number): Promise<number[]> {
    const gone = this.epochs().filter((e) => e < beforeEpoch);
    if (gone.length === 0) return [];
    const epochs = { ...this.#file.epochs };
    for (const e of gone) {
      delete epochs[String(e)];
      this.#pairs.delete(e);
    }
    this.#file = { ...this.#file, epochs };
    await this.#persist();
    return gone;
  }

  #persist(): Promise<void> {
    const run = async () => {
      const tmp = `${this.#path}.${crypto.randomUUID()}.tmp`;
      await Bun.write(tmp, `${JSON.stringify(this.#file, null, 2)}\n`);
      await Bun.$`chmod 600 ${tmp} && mv -f ${tmp} ${this.#path}`.quiet();
    };
    this.#writing = this.#writing.then(run, run);
    return this.#writing;
  }
}
