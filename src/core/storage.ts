import type { Logger } from "./log.ts";

export type FreeSpace = (dir: string) => Promise<number | null>;

const DF = ["/bin/df", "/usr/bin/df"];

export const freeMegabytes: FreeSpace = async (dir) => {
  try {
    let df: string | null = null;
    for (const path of DF) {
      if (await Bun.file(path).exists()) {
        df = path;
        break;
      }
    }
    if (!df) return null;
    const proc = Bun.spawn([df, "-Pk", dir], { stdout: "pipe", stderr: "ignore" });
    const [out, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    if (code !== 0) return null;
    const fields = out.trim().split("\n").at(-1)?.trim().split(/\s+/) ?? [];
    const kb = Number(fields[3]);
    return Number.isFinite(kb) ? Math.floor(kb / 1024) : null;
  } catch {
    return null;
  }
};

export interface StorageState {
  freeMb: number | null;
  minFreeMb: number;
  low: boolean;
}

export class StorageWatch {
  #free: number | null = null;
  #low = false;
  #warned = false;

  constructor(
    private readonly dir: string,
    private readonly minFreeMb: number,
    private readonly log: Logger,
    private readonly probe: FreeSpace = freeMegabytes,
  ) {}

  async check(): Promise<StorageState> {
    if (this.minFreeMb === 0) return this.state();
    const free = await this.probe(this.dir);
    this.#free = free;
    if (free === null) {
      if (!this.#warned) {
        this.#warned = true;
        this.log.warn("cannot read the free disk space; new email is not limited by it", {
          dir: this.dir,
        });
      }
      this.#low = false;
      return this.state();
    }
    const low = free < this.minFreeMb;
    if (low && !this.#low) {
      this.log.error("free disk space is low: new email is refused until space is freed", {
        dir: this.dir,
        free_mb: free,
        min_free_mb: this.minFreeMb,
      });
    } else if (!low && this.#low) {
      this.log.info("free disk space is back above the limit: new email is accepted", {
        free_mb: free,
      });
    }
    this.#low = low;
    return this.state();
  }

  low(): boolean {
    return this.#low;
  }

  state(): StorageState {
    return { freeMb: this.#free, minFreeMb: this.minFreeMb, low: this.#low };
  }
}
