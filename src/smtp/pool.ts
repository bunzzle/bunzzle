import type { SmtpConnection } from "./connection.ts";
import type { SessionInput, TlsRecord } from "./session.ts";

export interface Pooled {
  conn: SmtpConnection;
  ext: Map<string, string>;
  tls: TlsRecord;
  uses: number;
}

interface Idle {
  key: string;
  pooled: Pooled;
  timer: ReturnType<typeof setTimeout>;
}

export interface PoolOptions {
  idleMs?: number;
  maxIdlePerKey?: number;
  maxIdle?: number;
}

export class SessionPool {
  readonly #idle = new Map<string, Idle[]>();
  readonly #order = new Set<Idle>();
  readonly #busy = new Map<string, number>();
  readonly #idleMs: number;
  readonly #maxIdlePerKey: number;
  readonly #maxIdle: number;
  reusedCount = 0;

  constructor(o: PoolOptions = {}) {
    this.#idleMs = o.idleMs ?? 60_000;
    this.#maxIdlePerKey = o.maxIdlePerKey ?? 10;
    this.#maxIdle = o.maxIdle ?? 1_000;
  }

  #remove(idle: Idle) {
    clearTimeout(idle.timer);
    this.#order.delete(idle);
    const list = this.#idle.get(idle.key);
    if (!list) return;
    const i = list.indexOf(idle);
    if (i >= 0) list.splice(i, 1);
    if (list.length === 0) this.#idle.delete(idle.key);
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
      input.policy.rule === "dane" ? (input.names ?? []).join(",") : "",
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
    for (let idle = this.#idle.get(key)?.at(-1); idle; idle = this.#idle.get(key)?.at(-1)) {
      this.#remove(idle);
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
    if (list.length + (this.#busy.get(key) ?? 0) >= maxOpen || this.#maxIdle === 0) {
      void quit(pooled.conn);
      return;
    }
    const idle: Idle = {
      key,
      pooled,
      timer: setTimeout(() => {
        this.#remove(idle);
        void quit(pooled.conn);
      }, this.#idleMs),
    };
    list.push(idle);
    this.#idle.set(key, list);
    this.#order.add(idle);
    while (list.length > this.#maxIdlePerKey) this.#evict(list[0] as Idle);
    while (this.#order.size > this.#maxIdle) {
      this.#evict(this.#order.values().next().value as Idle);
    }
  }

  #evict(idle: Idle) {
    this.#remove(idle);
    void quit(idle.pooled.conn);
  }

  get size(): number {
    return this.#order.size;
  }

  get keys(): number {
    return this.#idle.size;
  }

  async closeAll() {
    const all = [...this.#order];
    for (const idle of all) this.#remove(idle);
    await Promise.all(all.map((idle) => quit(idle.pooled.conn)));
  }
}

async function quit(conn: SmtpConnection) {
  try {
    await conn.write("QUIT\r\n", 2_000);
    await conn.readReply(2_000);
  } catch {}
  conn.close();
}
