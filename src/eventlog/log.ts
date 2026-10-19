import type { FileSink } from "bun";

export interface EventLogOptions {
  dir: string;
  maxBytes: number;
  keepDays: number;
}

const NAME = /^events-(\d{8})-(\d{6})(?:-(\d+))?\.jsonl(\.gz)?$/;
const DAY = 86_400_000;

function stamp(ms: number): string {
  const iso = new Date(ms).toISOString();
  return `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}-${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}`;
}

function startOf(name: string): number | null {
  const m = NAME.exec(name);
  if (!m) return null;
  const [d, t] = [m[1] as string, m[2] as string];
  return Date.UTC(
    Number(d.slice(0, 4)),
    Number(d.slice(4, 6)) - 1,
    Number(d.slice(6, 8)),
    Number(t.slice(0, 2)),
    Number(t.slice(2, 4)),
    Number(t.slice(4, 6)),
  );
}

async function compress(path: string): Promise<void> {
  const gzip = Bun.file(path).stream().pipeThrough(new CompressionStream("gzip"));
  await Bun.write(`${path}.gz`, new Response(gzip));
  await Bun.file(path).delete();
}

export class EventLog {
  readonly #o: EventLogOptions;
  #sink: FileSink | null = null;
  #path: string | null = null;
  #day = "";
  #bytes = 0;

  constructor(o: EventLogOptions) {
    this.#o = { ...o, dir: o.dir.replace(/\/+$/, "") };
  }

  #files(): string[] {
    return [...new Bun.Glob("events-*.jsonl*").scanSync({ cwd: this.#o.dir })].sort();
  }

  async start(now: number): Promise<void> {
    for (const name of this.#files()) {
      if (name.endsWith(".jsonl")) await compress(`${this.#o.dir}/${name}`);
    }
    await this.prune(now);
  }

  async #open(now: number): Promise<void> {
    const base = `${this.#o.dir}/events-${stamp(now)}`;
    let path = `${base}.jsonl`;
    for (let n = 1; (await Bun.file(path).exists()) || (await Bun.file(`${path}.gz`).exists()); n++)
      path = `${base}-${n}.jsonl`;
    this.#path = path;
    this.#sink = Bun.file(path).writer();
    this.#day = stamp(now).slice(0, 8);
    this.#bytes = 0;
  }

  async #close(): Promise<void> {
    const path = this.#path;
    if (!this.#sink || !path) return;
    await this.#sink.end();
    this.#sink = null;
    this.#path = null;
    await compress(path);
  }

  async roll(now: number, adding = 0): Promise<void> {
    if (!this.#sink) return;
    const full = this.#bytes > 0 && this.#bytes + adding > this.#o.maxBytes;
    if (stamp(now).slice(0, 8) === this.#day && !full) return;
    await this.#close();
    await this.prune(now);
  }

  async write(lines: string[], now: number): Promise<void> {
    if (lines.length === 0) return;
    const text = lines.map((l) => `${l}\n`).join("");
    const size = new TextEncoder().encode(text).length;
    await this.roll(now, size);
    if (!this.#sink) await this.#open(now);
    const sink = this.#sink as FileSink;
    sink.write(text);
    await sink.flush();
    this.#bytes += size;
  }

  async prune(now: number): Promise<void> {
    const cutoff = now - this.#o.keepDays * DAY;
    for (const name of this.#files()) {
      if (!name.endsWith(".gz")) continue;
      const at = startOf(name);
      if (at !== null && at < cutoff) await Bun.file(`${this.#o.dir}/${name}`).delete();
    }
  }

  async stop(): Promise<void> {
    await this.#close();
  }
}
