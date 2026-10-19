export type Rng = () => number;

export function rng(seed: number): Rng {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x1_0000_0000;
  };
}

export const int = (r: Rng, n: number) => Math.floor(r() * n);
export const pick = <T>(r: Rng, items: readonly T[]): T => items[int(r, items.length)] as T;

const enc = new TextEncoder();
const INTERESTING = [
  0x00, 0x01, 0x0a, 0x0d, 0x20, 0x2e, 0x3a, 0x3b, 0x3c, 0x3e, 0x7f, 0x80, 0xc0, 0xff,
];

export function bytes(input: string | Uint8Array): Uint8Array {
  return typeof input === "string" ? enc.encode(input) : input;
}

export function mutate(
  r: Rng,
  input: Uint8Array,
  seeds: readonly Uint8Array[],
  dictionary: readonly Uint8Array[],
  maxLength: number,
): Uint8Array {
  let out = Array.from(input);
  const rounds = 1 + int(r, 6);
  for (let i = 0; i < rounds; i++) {
    const at = int(r, out.length + 1);
    switch (int(r, 10)) {
      case 0:
        if (out.length) out[at % out.length] = (out[at % out.length] as number) ^ (1 << int(r, 8));
        break;
      case 1:
        if (out.length) out[at % out.length] = int(r, 256);
        break;
      case 2:
        if (out.length) out[at % out.length] = pick(r, INTERESTING);
        break;
      case 3:
        out.splice(at, 0, ...Array.from({ length: 1 + int(r, 8) }, () => int(r, 256)));
        break;
      case 4:
        out.splice(at, 1 + int(r, Math.max(1, out.length >> 2)));
        break;
      case 5: {
        const len = 1 + int(r, Math.max(1, out.length >> 1));
        const from = int(r, Math.max(1, out.length - len));
        const chunk = out.slice(from, from + len);
        for (let k = 1 + int(r, 3); k > 0; k--) out.splice(at, 0, ...chunk);
        break;
      }
      case 6: {
        const other = Array.from(pick(r, seeds));
        const from = int(r, other.length + 1);
        out = out.slice(0, at).concat(other.slice(from, from + int(r, other.length + 1)));
        break;
      }
      case 7:
        if (dictionary.length) out.splice(at, 0, ...pick(r, dictionary));
        break;
      case 8:
        out = out.slice(0, at);
        break;
      default: {
        const word = 2 + int(r, 3);
        const v = pick(r, [0, 1, 0x7f, 0xff, 0xffff, 0xc000, 0x8000]);
        for (let k = 0; k < word && at + k < out.length; k++) out[at + k] = (v >> (8 * k)) & 0xff;
      }
    }
    if (out.length > maxLength) out = out.slice(0, maxLength);
  }
  return Uint8Array.from(out);
}

export interface Target {
  seeds: readonly (string | Uint8Array)[];
  dictionary?: readonly string[];
  maxLength?: number;
  iterations?: number;
  slowMs?: number;
  run(input: Uint8Array, r: Rng): unknown | Promise<unknown>;
  expected?(err: unknown): boolean;
}

export interface Finding {
  seed: number;
  iteration: number;
  input: string;
  size: number;
  error: string;
}

export const ITERATIONS = Number(Bun.env["BUNZZLE_FUZZ_ITERATIONS"] ?? 1_000);
export const SEED = Number(Bun.env["BUNZZLE_FUZZ_SEED"] ?? Date.now() % 0x7fff_ffff);

function describe(err: unknown): string {
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}

async function failure(t: Target, input: Uint8Array): Promise<string | null> {
  try {
    await t.run(input, rng(SEED));
    return null;
  } catch (err) {
    return t.expected?.(err) ? null : describe(err);
  }
}

function without(input: Uint8Array, at: number, n: number): Uint8Array {
  const out = new Uint8Array(input.length - n);
  out.set(input.subarray(0, at));
  out.set(input.subarray(at + n), at);
  return out;
}

export async function shrink(
  t: Target,
  input: Uint8Array,
  { runs = 2_000, ms = 10_000 } = {},
): Promise<Uint8Array> {
  const deadline = performance.now() + ms;
  let best = input;
  let left = runs;
  let chunk = best.length >> 1;
  while (chunk >= 1 && left > 0 && performance.now() < deadline) {
    let removed = false;
    for (let at = 0; at + chunk <= best.length && left > 0 && performance.now() < deadline; ) {
      const candidate = without(best, at, chunk);
      left--;
      if ((await failure(t, candidate)) !== null) {
        best = candidate;
        removed = true;
      } else {
        at += chunk;
      }
    }
    if (!removed) chunk >>= 1;
    else chunk = Math.min(chunk, best.length >> 1);
  }
  return best;
}

export async function fuzz(t: Target): Promise<Finding[]> {
  const seeds = t.seeds.map(bytes);
  const dictionary = (t.dictionary ?? []).map(bytes);
  const maxLength = t.maxLength ?? 64 * 1024;
  const iterations = Math.ceil(ITERATIONS * (t.iterations ?? 1));
  const slowMs = t.slowMs ?? 1_000;
  const r = rng(SEED);
  const findings: Finding[] = [];
  for (let i = 0; i < iterations && findings.length < 5; i++) {
    const base = i < seeds.length ? (seeds[i] as Uint8Array) : pick(r, seeds);
    const input = i < seeds.length ? base : mutate(r, base, seeds, dictionary, maxLength);
    const started = performance.now();
    try {
      await t.run(input, r);
    } catch (err) {
      if (!t.expected?.(err)) {
        const small = await shrink(t, input);
        findings.push({
          seed: SEED,
          iteration: i,
          input: small.toBase64(),
          size: input.length,
          error: (await failure(t, small)) ?? describe(err),
        });
        continue;
      }
    }
    const took = performance.now() - started;
    if (took > slowMs) {
      findings.push({
        seed: SEED,
        iteration: i,
        input: input.toBase64(),
        size: input.length,
        error: `slow: ${Math.round(took)} ms`,
      });
    }
  }
  return findings;
}

export function report(findings: Finding[]): string {
  return findings
    .map((f) => {
      const n = Uint8Array.fromBase64(f.input).length;
      const from = n < f.size ? `, shrunk from ${f.size} to ${n} bytes` : "";
      return `seed ${f.seed} iteration ${f.iteration}: ${f.error}${from}\n  input (base64): ${f.input.slice(0, 2_000)}`;
    })
    .join("\n");
}
