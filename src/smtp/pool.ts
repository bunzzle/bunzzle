import type { SmtpConnection } from "./connection.ts";
import type { SessionInput, TlsRecord } from "./session.ts";

export interface Pooled {
  conn: SmtpConnection;
  ext: Map<string, string>;
  tls: TlsRecord;
  uses: number;
}

interface Idle {
  pooled: Pooled;
  timer: ReturnType<typeof setTimeout>;
}

export interface PoolOptions {
  idleMs?: number;
  maxIdlePerKey?: number;
}

export class SessionPool {
  readonly #idle = new Map<string, Idle[]>();
  readonly #busy = new Map<string, number>();
  readonly #idleMs: number;
  readonly #maxIdle: number;
  reusedCount = 0;

  constructor(o: PoolOptions = {}) {
    this.#idleMs = o.idleMs ?? 60_000;
    this.#maxIdle = o.maxIdlePerKey ?? 10;
  }

  static key(input: SessionInput): string {
    return [
      input.host,
      input.address,
      input.port,
      input.localAddress ?? "",
      input.ehloName,
      input.policy.rule,
      input.policy.required ? "tls" : "",
    ].join("|");
  }

  #begin(key: string) {
    this.#busy.set(key, (this.#busy.get(key) ?? 0) + 1);
  }

  done(key: string) {
    const n = (this.#busy.get(key) ?? 1) - 1;
    if (n > 0) this.#busy.set(key, n);
    else this.#busy.delete(key);
  }

  take(key: string): Pooled | null {
    this.#begin(key);
    const list = this.#idle.get(key);
    while (list && list.length > 0) {
      const idle = list.pop() as Idle;
      clearTimeout(idle.timer);
      if (!idle.pooled.conn.closed && !idle.pooled.conn.hasBufferedData()) {
        this.reusedCount++;
        return idle.pooled;
      }
      idle.pooled.conn.close();
    }
    return null;
  }

  give(key: string, pooled: Pooled, maxOpen = Number.POSITIVE_INFINITY) {
    this.done(key);
    const list = this.#idle.get(key) ?? [];
    if (list.length + (this.#busy.get(key) ?? 0) >= maxOpen) {
      void quit(pooled.conn);
      return;
    }
    const timer = setTimeout(() => {
      const i = list.findIndex((x) => x.pooled === pooled);
      if (i >= 0) list.splice(i, 1);
      void quit(pooled.conn);
    }, this.#idleMs);
    list.push({ pooled, timer });
    while (list.length > this.#maxIdle) {
      const oldest = list.shift() as Idle;
      clearTimeout(oldest.timer);
      void quit(oldest.pooled.conn);
    }
    this.#idle.set(key, list);
  }

  get size(): number {
    let n = 0;
    for (const list of this.#idle.values()) n += list.length;
    return n;
  }

  async closeAll() {
    const all = [...this.#idle.values()].flat();
    this.#idle.clear();
    await Promise.all(
      all.map((idle) => {
        clearTimeout(idle.timer);
        return quit(idle.pooled.conn);
      }),
    );
  }
}

async function quit(conn: SmtpConnection) {
  try {
    await conn.write("QUIT\r\n", 2_000);
    await conn.readReply(2_000);
  } catch {}
  conn.close();
}
