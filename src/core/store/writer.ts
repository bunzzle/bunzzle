import type { Database } from "bun:sqlite";

export interface WriterOptions {
  maxBatch?: number;
}

export class Writer {
  readonly #db: Database;
  readonly #maxBatch: number;
  #queue: Pending[] = [];
  #scheduled = false;
  #closed = false;
  readonly #listeners = new Set<() => void>();

  constructor(db: Database, { maxBatch = 256 }: WriterOptions = {}) {
    this.#db = db;
    this.#maxBatch = maxBatch;
  }

  run<T>(op: (db: Database) => T, { quiet = false }: { quiet?: boolean } = {}): Promise<T> {
    if (this.#closed) return Promise.reject(new Error("writer is closed"));
    const { promise, resolve, reject } = Promise.withResolvers<T>();
    this.#queue.push({ op, quiet, resolve: resolve as (v: unknown) => void, reject });
    if (this.#queue.length >= this.#maxBatch) this.#flush();
    else if (!this.#scheduled) {
      this.#scheduled = true;
      setImmediate(() => this.#flush());
    }
    return promise;
  }

  onCommit(fn: () => void): () => void {
    this.#listeners.add(fn);
    return () => this.#listeners.delete(fn);
  }

  close(): void {
    while (this.#queue.length > 0) this.#flush();
    this.#closed = true;
  }

  #flush(): void {
    this.#scheduled = false;
    if (this.#queue.length === 0) return;
    const batch = this.#queue.splice(0, this.#maxBatch);
    if (this.#queue.length > 0 && !this.#scheduled) {
      this.#scheduled = true;
      setImmediate(() => this.#flush());
    }

    const results: Array<{ ok: true; value: unknown } | { ok: false; error: unknown }> = [];
    try {
      this.#db
        .transaction(() => {
          for (const p of batch) {
            try {
              results.push({ ok: true, value: this.#db.transaction(p.op)(this.#db) });
            } catch (error) {
              results.push({ ok: false, error });
            }
          }
        })
        .immediate();
    } catch (error) {
      for (const p of batch) p.reject(error);
      return;
    }

    batch.forEach((p, i) => {
      const r = results[i];
      if (r?.ok) p.resolve(r.value);
      else p.reject(r?.error);
    });
    if (batch.some((p) => !p.quiet)) for (const fn of this.#listeners) fn();
  }
}

interface Pending {
  op: (db: Database) => unknown;
  quiet: boolean;
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
}
