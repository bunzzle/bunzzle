import { expect, test } from "bun:test";
import { z } from "zod";
import { b } from "../../src/validate/schema.ts";
import { ITERATIONS, int, pick, type Rng, rng, SEED } from "./engine.ts";

type Spec =
  | { t: "string"; min?: number; max?: number; regex?: RegExp; url?: boolean }
  | {
      t: "number";
      int?: boolean;
      min?: number;
      max?: number;
      positive?: boolean;
      nonneg?: boolean;
      coerce?: boolean;
    }
  | { t: "boolean" }
  | { t: "unknown" }
  | { t: "literal"; v: string | number | boolean | null }
  | { t: "enum"; vs: [string, ...string[]] }
  | { t: "object"; shape: Record<string, Spec> }
  | { t: "array"; el: Spec; min?: number; max?: number }
  | { t: "record"; key: RegExp | null; v: Spec }
  | { t: "union"; opts: Spec[] }
  | { t: "disc"; opts: { tag: string; shape: Record<string, Spec> }[] }
  | { t: "optional"; inner: Spec }
  | { t: "nullable"; inner: Spec }
  | { t: "default"; inner: Spec; d: unknown };

const KEYS = ["a", "b", "kind", "id", "x y"];
const WORDS = [
  "",
  "a",
  "abc",
  "hello world",
  "x".repeat(70),
  "123",
  "1e3",
  " 42 ",
  "true",
  "https://x.test/p",
  "ftp://h",
  "not a url",
  "Ünlü",
  "\u0000",
];

function spec(r: Rng, depth: number): Spec {
  const leaf = depth >= 3 || r() < 0.4;
  if (leaf) {
    switch (int(r, 6)) {
      case 0:
        return {
          t: "string",
          ...(r() < 0.4 ? { min: int(r, 4) } : {}),
          ...(r() < 0.4 ? { max: 2 + int(r, 20) } : {}),
          ...(r() < 0.2 ? { regex: pick(r, [/^[a-z]+$/, /\d/, /^a/i]) } : {}),
          ...(r() < 0.1 ? { url: true } : {}),
        };
      case 1:
        return {
          t: "number",
          ...(r() < 0.5 ? { int: true } : {}),
          ...(r() < 0.3 ? { min: int(r, 10) - 5 } : {}),
          ...(r() < 0.3 ? { max: int(r, 100) } : {}),
          ...(r() < 0.1 ? { positive: true } : {}),
          ...(r() < 0.1 ? { nonneg: true } : {}),
          ...(r() < 0.2 ? { coerce: true } : {}),
        };
      case 2:
        return { t: "boolean" };
      case 3:
        return { t: "literal", v: pick(r, ["x", 4, 6, true, null]) };
      case 4:
        return {
          t: "enum",
          vs: pick(r, [["a"], ["a", "b", "c"], ["true", "1"]]) as [string, ...string[]],
        };
      default:
        return { t: "unknown" };
    }
  }
  const inner = () => spec(r, depth + 1);
  switch (int(r, 8)) {
    case 0:
    case 1: {
      const shape: Record<string, Spec> = {};
      for (let k = 1 + int(r, 3); k > 0; k--) shape[pick(r, KEYS)] = inner();
      return { t: "object", shape };
    }
    case 2:
      return {
        t: "array",
        el: inner(),
        ...(r() < 0.3 ? { min: int(r, 3) } : {}),
        ...(r() < 0.3 ? { max: 1 + int(r, 4) } : {}),
      };
    case 3:
      return { t: "record", key: r() < 0.5 ? null : /^[a-z]+$/, v: inner() };
    case 4:
      return { t: "union", opts: [inner(), inner()] };
    case 5:
      return {
        t: "disc",
        opts: [
          { tag: "one", shape: { n: inner() } },
          { tag: "two", shape: { m: inner() } },
        ],
      };
    case 6:
      return { t: r() < 0.5 ? "optional" : "nullable", inner: inner() };
    default: {
      const s = inner();
      return { t: "default", inner: s, d: sample(r, s, 0) ?? "d" };
    }
  }
}

type Lib = typeof z | typeof b;
type Built = {
  min(n: number): Built;
  max(n: number): Built;
  regex(r: RegExp): Built;
  url(): Built;
  int(): Built;
  positive(): Built;
  nonnegative(): Built;
  optional(): Built;
  nullable(): Built;
  default(v: unknown): Built;
  safeParse(
    v: unknown,
  ):
    | { success: true; data: unknown }
    | { success: false; error: { issues: { message: string }[] } };
};
type Builders = {
  string(): Built;
  number(): Built;
  boolean(): Built;
  unknown(): Built;
  literal(v: unknown): Built;
  enum(v: readonly string[]): Built;
  object(s: Record<string, Built>): Built;
  array(e: Built): Built;
  record(k: Built, v: Built): Built;
  union(o: Built[]): Built;
  discriminatedUnion(k: string, o: Built[]): Built;
  coerce: { number(): Built };
};

function build(lib: Lib, s: Spec): Built {
  const L = lib as unknown as Builders;
  switch (s.t) {
    case "string": {
      let x = L.string();
      if (s.min !== undefined) x = x.min(s.min);
      if (s.max !== undefined) x = x.max(s.max);
      if (s.regex) x = x.regex(s.regex);
      if (s.url) x = x.url();
      return x;
    }
    case "number": {
      let x = s.coerce ? L.coerce.number() : L.number();
      if (s.int) x = x.int();
      if (s.min !== undefined) x = x.min(s.min);
      if (s.max !== undefined) x = x.max(s.max);
      if (s.positive) x = x.positive();
      if (s.nonneg) x = x.nonnegative();
      return x;
    }
    case "boolean":
      return L.boolean();
    case "unknown":
      return L.unknown();
    case "literal":
      return L.literal(s.v);
    case "enum":
      return L.enum(s.vs);
    case "object":
      return L.object(
        Object.fromEntries(Object.entries(s.shape).map(([k, v]) => [k, build(lib, v)])),
      );
    case "array": {
      let x = L.array(build(lib, s.el));
      if (s.min !== undefined) x = x.min(s.min);
      if (s.max !== undefined) x = x.max(s.max);
      return x;
    }
    case "record":
      return L.record(s.key ? L.string().regex(s.key) : L.string(), build(lib, s.v));
    case "union":
      return L.union(s.opts.map((o) => build(lib, o)));
    case "disc":
      return L.discriminatedUnion(
        "kind",
        s.opts.map((o) =>
          L.object({
            kind: L.literal(o.tag),
            ...Object.fromEntries(Object.entries(o.shape).map(([k, v]) => [k, build(lib, v)])),
          }),
        ),
      );
    case "optional":
      return build(lib, s.inner).optional();
    case "nullable":
      return build(lib, s.inner).nullable();
    case "default":
      return build(lib, s.inner).default(s.d);
  }
}

function noise(r: Rng): unknown {
  return pick(r, [
    undefined,
    null,
    0,
    -1,
    1.5,
    7,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    "",
    "7",
    "abc",
    true,
    false,
    [],
    {},
    [1, "a"],
    { kind: "one" },
  ]);
}

function sample(r: Rng, s: Spec, depth: number): unknown {
  if (r() < 0.12 || depth > 6) return noise(r);
  switch (s.t) {
    case "string":
      return pick(r, WORDS).slice(0, s.max !== undefined && r() < 0.7 ? s.max : undefined);
    case "number":
      return s.coerce && r() < 0.5
        ? String(int(r, 200) - 50)
        : r() < 0.8
          ? int(r, 200) - 50
          : r() * 10;
    case "boolean":
      return r() < 0.5;
    case "unknown":
      return noise(r);
    case "literal":
      return r() < 0.8 ? s.v : noise(r);
    case "enum":
      return r() < 0.8 ? pick(r, s.vs) : "zz";
    case "object": {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(s.shape)) {
        if (r() < 0.85)
          Object.defineProperty(out, k, {
            value: sample(r, v, depth + 1),
            enumerable: true,
            writable: true,
            configurable: true,
          });
      }
      if (r() < 0.3) out["extra"] = 1;
      return out;
    }
    case "array":
      return Array.from({ length: int(r, 5) }, () => sample(r, s.el, depth + 1));
    case "record": {
      const out: Record<string, unknown> = {};
      for (let k = int(r, 3); k > 0; k--)
        out[pick(r, ["a", "bc", "X1", ""])] = sample(r, s.v, depth + 1);
      return out;
    }
    case "union":
      return sample(r, pick(r, s.opts), depth + 1);
    case "disc": {
      const o = pick(r, s.opts);
      return {
        kind: r() < 0.9 ? o.tag : "three",
        ...(sample(r, { t: "object", shape: o.shape }, depth + 1) as object),
      };
    }
    case "optional":
    case "nullable":
    case "default":
      return r() < 0.3 ? (s.t === "nullable" ? null : undefined) : sample(r, s.inner, depth + 1);
  }
}

function hasUrl(s: Spec): boolean {
  return JSON.stringify(s, (_, v) => (v instanceof RegExp ? String(v) : v)).includes('"url":true');
}

test(
  "the new validator agrees with the old one on random schemas and values",
  () => {
    const r = rng(SEED);
    const findings: string[] = [];
    const schemas = Math.ceil(ITERATIONS / 2);
    for (let n = 0; n < schemas && findings.length < 5; n++) {
      const s = spec(r, 0);
      const zs = build(z, s);
      const bs = build(b, s);
      for (let k = 0; k < 20; k++) {
        const value = sample(r, s, 0);
        const a = zs.safeParse(value);
        const c = bs.safeParse(value);
        const same =
          a.success && c.success ? Bun.deepEquals(a.data, c.data) : a.success === c.success;
        if (!same && !(hasUrl(s) && a.success !== c.success)) {
          findings.push(
            `seed ${SEED} schema ${n}: ${JSON.stringify(s, (_, v) => (v instanceof RegExp ? String(v) : v))}\n  value ${show(value)}\n  old ${a.success ? show(a.data) : a.error.issues[0]?.message}\n  new ${c.success ? show(c.data) : c.error.issues[0]?.message}`,
          );
          break;
        }
      }
    }
    expect(findings.join("\n")).toBe("");
  },
  { timeout: 30 * 60_000 },
);

function show(v: unknown): string {
  return (
    JSON.stringify(v, (_, x) =>
      x === undefined ? "<undefined>" : Number.isNaN(x) ? "<NaN>" : x,
    ) ?? "<undefined>"
  );
}
