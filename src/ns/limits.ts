import { parseIPv4, parseIPv6 } from "../dns/ip.ts";
import type { Kind } from "./answer.ts";

export interface LimitOptions {
  v4Prefix: number;
  v6Prefix: number;
  rates: Record<Kind, { perSec: number; burst: number }>;
  globalPerSec: number;
  maxEntries: number;
}

export const DEFAULT_LIMITS: LimitOptions = {
  v4Prefix: 24,
  v6Prefix: 56,
  rates: {
    answer: { perSec: 20, burst: 40 },
    negative: { perSec: 20, burst: 40 },
    error: { perSec: 5, burst: 10 },
  },
  globalPerSec: 20_000,
  maxEntries: 100_000,
};

export type Verdict = "send" | "slip" | "drop" | "global";

interface Bucket {
  tokens: number;
  at: number;
  over: number;
}

function masked(bytes: Uint8Array, bits: number): string {
  let out = "";
  for (let i = 0; i < bytes.length && i * 8 < bits; i++) {
    const keep = Math.min(8, bits - i * 8);
    const byte = (bytes[i] as number) & (0xff << (8 - keep)) & 0xff;
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

export function networkOf(address: string, v4Prefix: number, v6Prefix: number): string {
  const v4 = parseIPv4(address.startsWith("::ffff:") ? address.slice(7) : address);
  if (v4) return `4:${masked(v4, v4Prefix)}`;
  const v6 = parseIPv6(address);
  if (v6) return `6:${masked(v6, v6Prefix)}`;
  return `?:${address}`;
}

export class ResponseLimiter {
  readonly #buckets = new Map<string, Bucket>();
  readonly #global: Bucket;

  constructor(
    private readonly opts: LimitOptions = DEFAULT_LIMITS,
    private readonly now: () => number = Date.now,
  ) {
    this.#global = { tokens: opts.globalPerSec, at: now(), over: 0 };
  }

  get size(): number {
    return this.#buckets.size;
  }

  #take(b: Bucket, perSec: number, burst: number, t: number): boolean {
    b.tokens = Math.min(burst, b.tokens + ((t - b.at) * perSec) / 1000);
    b.at = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  check(address: string, kind: Kind): Verdict {
    const t = this.now();
    const rate = this.opts.rates[kind];
    const key = `${networkOf(address, this.opts.v4Prefix, this.opts.v6Prefix)}/${kind}`;
    let b = this.#buckets.get(key);
    if (b) this.#buckets.delete(key);
    else {
      b = { tokens: rate.burst, at: t, over: 0 };
      if (this.#buckets.size >= this.opts.maxEntries) {
        const oldest = this.#buckets.keys().next().value;
        if (oldest !== undefined) this.#buckets.delete(oldest);
      }
    }
    this.#buckets.set(key, b);
    if (!this.#take(b, rate.perSec, rate.burst, t)) return ++b.over % 2 === 0 ? "drop" : "slip";
    b.over = 0;
    const g = this.opts.globalPerSec;
    return this.#take(this.#global, g, g, t) ? "send" : "global";
  }
}
