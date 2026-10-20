export type Path = (string | number)[];

export type JsonSchema = Record<string, unknown>;

function nullableJson(j: JsonSchema): JsonSchema {
  if (typeof j["type"] === "string") {
    return {
      ...j,
      type: [j["type"], "null"],
      ...(Array.isArray(j["enum"]) ? { enum: [...j["enum"], null] } : {}),
    };
  }
  return { anyOf: [j, { type: "null" }] };
}

export interface Issue {
  path: Path;
  message: string;
}

export class ValidationError extends Error {
  constructor(readonly issues: Issue[]) {
    super(issues.map((i) => `${i.path.join(".") || "value"}: ${i.message}`).join("; "));
    this.name = "ValidationError";
  }
}

export type Result<T> = { success: true; data: T } | { success: false; error: ValidationError };

const FAIL: unique symbol = Symbol("fail");
type Fail = typeof FAIL;
type Check<O> = (value: unknown, path: Path, issues: Issue[]) => O | Fail;

function kind(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number" && Number.isNaN(v)) return "NaN";
  return typeof v;
}

function fail(issues: Issue[], path: Path, message: string): Fail {
  issues.push({ path, message });
  return FAIL;
}

function expected(issues: Issue[], path: Path, want: string, v: unknown): Fail {
  return fail(issues, path, v === undefined ? "is required" : `expected ${want}, got ${kind(v)}`);
}

function copy<T>(v: T): T {
  return typeof v === "object" && v !== null ? structuredClone(v) : v;
}

function define(target: Record<string, unknown>, key: string, value: unknown) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class Schema<O, I = O, OptOut extends boolean = false, OptIn extends boolean = OptOut> {
  declare readonly _output: O;
  declare readonly _input: I;
  declare readonly _optOut: OptOut;
  declare readonly _optIn: OptIn;

  constructor(
    readonly check: Check<O>,
    readonly optionalKey = false,
    readonly json: JsonSchema = {},
  ) {}

  describe(description: string): Schema<O, I, OptOut, OptIn> {
    return new Schema(this.check, this.optionalKey, { ...this.json, description });
  }

  safeParse(value: unknown): Result<O> {
    const issues: Issue[] = [];
    const out = this.check(value, [], issues);
    if (out === FAIL || issues.length > 0) {
      if (issues.length === 0) issues.push({ path: [], message: "is invalid" });
      return { success: false, error: new ValidationError(issues) };
    }
    return { success: true, data: out };
  }

  parse(value: unknown): O {
    const r = this.safeParse(value);
    if (!r.success) throw r.error;
    return r.data;
  }

  optional(): Schema<O | undefined, I | undefined, true, true> {
    return new Schema<O | undefined, I | undefined, true, true>(
      (v, p, i) => (v === undefined && !this.optionalKey ? undefined : this.check(v, p, i)),
      true,
      this.json,
    );
  }

  nullable(): Schema<O | null, I | null, OptOut, OptIn> {
    return new Schema<O | null, I | null, OptOut, OptIn>(
      (v, p, i) => (v === null ? null : this.check(v, p, i)),
      this.optionalKey,
      nullableJson(this.json),
    );
  }

  default(value: Exclude<O, undefined>): Schema<Exclude<O, undefined>, I | undefined, false, true> {
    return new Schema(
      (v, p, i) =>
        (v === undefined ? copy(value) : this.check(v, p, i)) as Exclude<O, undefined> | Fail,
      true,
      { ...this.json, default: value },
    );
  }

  transform<N>(fn: (value: O) => N): Schema<N, I, false, OptIn> {
    return new Schema(
      (v, p, i) => {
        const out = this.check(v, p, i);
        return out === FAIL ? FAIL : fn(out);
      },
      this.optionalKey,
      this.json,
    );
  }

  refine(
    ok: (value: O) => boolean,
    opts: { message?: string } | string = {},
  ): Schema<O, I, OptOut, OptIn> {
    const message = typeof opts === "string" ? opts : (opts.message ?? "is invalid");
    return new Schema(
      (v, p, i) => {
        const out = this.check(v, p, i);
        if (out === FAIL) return FAIL;
        return ok(out) ? out : fail(i, p, message);
      },
      this.optionalKey,
      this.json,
    );
  }
}

type Rule<T> = (value: T) => string | null;

function withRules<T>(base: Check<T>, rules: Rule<T>[]): Check<T> {
  return (v, p, i) => {
    const out = base(v, p, i);
    if (out === FAIL) return FAIL;
    let ok = true;
    for (const rule of rules) {
      const message = rule(out);
      if (message !== null) {
        fail(i, p, message);
        ok = false;
      }
    }
    return ok ? out : FAIL;
  };
}

const EMAIL =
  /^[^\s@"<>()[\],;:\\]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;

export class StringSchema extends Schema<string> {
  constructor(
    private readonly rules: Rule<string>[] = [],
    json: JsonSchema = { type: "string" },
  ) {
    super(
      withRules((v, p, i) => (typeof v === "string" ? v : expected(i, p, "string", v)), rules),
      false,
      json,
    );
  }

  #with(rule: Rule<string>, json: JsonSchema): StringSchema {
    return new StringSchema([...this.rules, rule], { ...this.json, ...json });
  }

  min(n: number): StringSchema {
    return this.#with((s) => (s.length >= n ? null : `must be at least ${n} characters`), {
      minLength: n,
    });
  }

  max(n: number): StringSchema {
    return this.#with((s) => (s.length <= n ? null : `must be at most ${n} characters`), {
      maxLength: n,
    });
  }

  regex(re: RegExp, message = "has an invalid format"): StringSchema {
    return this.#with(
      (s) => {
        re.lastIndex = 0;
        return re.test(s) ? null : message;
      },
      { pattern: re.source },
    );
  }

  email(): StringSchema {
    return this.#with((s) => (EMAIL.test(s) ? null : "must be an email address"), {
      format: "email",
    });
  }

  format(name: string): StringSchema {
    return this.#with(() => null, { format: name });
  }

  url(): StringSchema {
    return this.#with((s) => (URL.canParse(s) ? null : "must be a URL"), { format: "uri" });
  }
}

export class NumberSchema extends Schema<number> {
  constructor(
    private readonly rules: Rule<number>[] = [],
    private readonly coerce = false,
    json: JsonSchema = { type: "number" },
  ) {
    super(
      withRules((v, p, i) => {
        const n = coerce && v !== undefined ? Number(v) : v;
        return typeof n === "number" && Number.isFinite(n) ? n : expected(i, p, "number", v);
      }, rules),
      false,
      json,
    );
  }

  #with(rule: Rule<number>, json: JsonSchema): NumberSchema {
    return new NumberSchema([...this.rules, rule], this.coerce, { ...this.json, ...json });
  }

  int(): NumberSchema {
    return this.#with((n) => (Number.isSafeInteger(n) ? null : "must be a whole number"), {
      type: "integer",
    });
  }

  min(n: number): NumberSchema {
    return this.#with((x) => (x >= n ? null : `must be at least ${n}`), { minimum: n });
  }

  max(n: number): NumberSchema {
    return this.#with((x) => (x <= n ? null : `must be at most ${n}`), { maximum: n });
  }

  positive(): NumberSchema {
    return this.#with((x) => (x > 0 ? null : "must be greater than 0"), { exclusiveMinimum: 0 });
  }

  nonnegative(): NumberSchema {
    return this.#with((x) => (x >= 0 ? null : "must be 0 or more"), { minimum: 0 });
  }
}

type AnySchema = Schema<unknown, unknown, boolean, boolean>;
export type Output<S> = S extends Schema<infer O, unknown, boolean, boolean> ? O : never;
export type Input<S> = S extends Schema<unknown, infer I, boolean, boolean> ? I : never;
type Pretty<T> = { [K in keyof T]: T[K] } & {};
type Shape = Record<string, AnySchema>;

type ObjectOutput<S extends Shape> = Pretty<
  { [K in keyof S as S[K]["_optOut"] extends true ? K : never]?: Output<S[K]> } & {
    [K in keyof S as S[K]["_optOut"] extends true ? never : K]: Output<S[K]>;
  }
>;

type ObjectInput<S extends Shape> = Pretty<
  { [K in keyof S as S[K]["_optIn"] extends true ? K : never]?: Input<S[K]> } & {
    [K in keyof S as S[K]["_optIn"] extends true ? never : K]: Input<S[K]>;
  }
>;

export class ObjectSchema<S extends Shape> extends Schema<ObjectOutput<S>, ObjectInput<S>> {
  constructor(readonly shape: S) {
    const keys = Object.keys(shape);
    super(
      (v, p, i) => {
        if (!isObject(v)) return expected(i, p, "object", v);
        const out: Record<string, unknown> = {};
        let ok = true;
        for (const k of keys) {
          const has = Object.hasOwn(v, k);
          const field = shape[k] as AnySchema;
          if (!has && !field.optionalKey) {
            const r = field.check(undefined, [...p, k], i);
            if (r === FAIL || r === undefined) {
              if (r === undefined) fail(i, [...p, k], "is required");
              ok = false;
              continue;
            }
            define(out, k, r);
            continue;
          }
          const r = field.check(has ? v[k] : undefined, [...p, k], i);
          if (r === FAIL) ok = false;
          else if (r !== undefined || has) define(out, k, r);
        }
        return ok ? (out as ObjectOutput<S>) : FAIL;
      },
      false,
      {
        type: "object",
        properties: Object.fromEntries(keys.map((k) => [k, (shape[k] as AnySchema).json])),
        required: keys.filter((k) => !(shape[k] as AnySchema).optionalKey),
      },
    );
  }

  omit<K extends keyof S & string>(mask: { [k in K]: true }): ObjectSchema<Omit<S, K>> {
    const shape: Record<string, AnySchema> = {};
    for (const [k, s] of Object.entries(this.shape)) if (!(k in mask)) shape[k] = s;
    return new ObjectSchema(shape as Omit<S, K>);
  }
}

export class ArraySchema<T extends AnySchema> extends Schema<Output<T>[], Input<T>[]> {
  constructor(
    readonly element: T,
    private readonly rules: Rule<unknown[]>[] = [],
    json: JsonSchema = { type: "array", items: element.json },
  ) {
    super(
      withRules((v, p, i) => {
        if (!Array.isArray(v)) return expected(i, p, "array", v);
        const out: Output<T>[] = [];
        let ok = true;
        for (let n = 0; n < v.length; n++) {
          const r = element.check(v[n], [...p, n], i);
          if (r === FAIL) ok = false;
          else out.push(r as Output<T>);
        }
        return ok ? out : FAIL;
      }, rules) as Check<Output<T>[]>,
      false,
      json,
    );
  }

  #with(rule: Rule<unknown[]>, json: JsonSchema): ArraySchema<T> {
    return new ArraySchema(this.element, [...this.rules, rule], { ...this.json, ...json });
  }

  min(n: number): ArraySchema<T> {
    return this.#with((a) => (a.length >= n ? null : `must have at least ${n} items`), {
      minItems: n,
    });
  }

  max(n: number): ArraySchema<T> {
    return this.#with((a) => (a.length <= n ? null : `must have at most ${n} items`), {
      maxItems: n,
    });
  }
}

export class LiteralSchema<V extends string | number | boolean | null> extends Schema<V> {
  constructor(readonly value: V) {
    super(
      (v, p, i) =>
        v === value
          ? value
          : fail(i, p, v === undefined ? "is required" : `must be ${JSON.stringify(value)}`),
      false,
      { const: value },
    );
  }
}

function string(): StringSchema {
  return new StringSchema();
}

function number(): NumberSchema {
  return new NumberSchema();
}

function boolean(): Schema<boolean> {
  return new Schema(
    (v, p, i) => (typeof v === "boolean" ? v : expected(i, p, "boolean", v)),
    false,
    { type: "boolean" },
  );
}

function unknown(): Schema<unknown> {
  return new Schema((v) => v);
}

function literal<const V extends string | number | boolean | null>(value: V): LiteralSchema<V> {
  return new LiteralSchema(value);
}

function enumOf<const T extends readonly [string, ...string[]]>(values: T): Schema<T[number]> {
  const set = new Set<string>(values);
  return new Schema(
    (v, p, i) =>
      typeof v === "string" && set.has(v)
        ? (v as T[number])
        : fail(i, p, v === undefined ? "is required" : `must be one of: ${values.join(", ")}`),
    false,
    { type: "string", enum: [...values] },
  );
}

function object<S extends Shape>(shape: S): ObjectSchema<S> {
  return new ObjectSchema(shape);
}

function array<T extends AnySchema>(element: T): ArraySchema<T> {
  return new ArraySchema(element);
}

function tuple<const T extends readonly AnySchema[]>(
  items: T,
): Schema<{ -readonly [k in keyof T]: Output<T[k]> }, { -readonly [k in keyof T]: Input<T[k]> }> {
  return new Schema(
    (v, p, i) => {
      if (!Array.isArray(v)) return expected(i, p, "array", v);
      if (v.length !== items.length) return fail(i, p, `must have exactly ${items.length} items`);
      const out: unknown[] = [];
      let ok = true;
      items.forEach((item, n) => {
        const r = item.check(v[n], [...p, n], i);
        if (r === FAIL) ok = false;
        else out.push(r);
      });
      return ok ? (out as { -readonly [k in keyof T]: Output<T[k]> }) : FAIL;
    },
    false,
    {
      type: "array",
      prefixItems: items.map((x) => x.json),
      minItems: items.length,
      maxItems: items.length,
    },
  );
}

function record<K extends Schema<string, unknown, boolean, boolean>, V extends AnySchema>(
  keys: K,
  values: V,
): Schema<Record<Output<K>, Output<V>>, Record<Input<K> & string, Input<V>>> {
  return new Schema(
    (v, p, i) => {
      if (!isObject(v)) return expected(i, p, "object", v);
      const out: Record<string, unknown> = {};
      let ok = true;
      for (const k of Object.keys(v)) {
        const key = keys.check(k, [...p, k], i);
        const value = values.check(v[k], [...p, k], i);
        if (key === FAIL || value === FAIL) ok = false;
        else define(out, key, value);
      }
      return ok ? (out as Record<Output<K>, Output<V>>) : FAIL;
    },
    false,
    { type: "object", additionalProperties: values.json },
  );
}

function union<const T extends readonly AnySchema[]>(
  options: T,
): Schema<Output<T[number]>, Input<T[number]>> {
  return new Schema<Output<T[number]>, Input<T[number]>>(
    (v, p, i) => {
      for (const option of options) {
        const tried: Issue[] = [];
        const out = option.check(v, p, tried);
        if (out !== FAIL && tried.length === 0) return out as Output<T[number]>;
      }
      return fail(i, p, v === undefined ? "is required" : "does not match any allowed form");
    },
    options.some((o) => o.optionalKey),
    { anyOf: options.map((o) => o.json) },
  );
}

function discriminatedUnion<
  K extends string,
  const T extends readonly ObjectSchema<
    { [k in K]: LiteralSchema<string | number | boolean | null> } & Shape
  >[],
>(key: K, options: T): Schema<Output<T[number]>, Input<T[number]>> {
  const byValue = new Map<unknown, AnySchema>();
  for (const o of options)
    byValue.set((o.shape[key] as LiteralSchema<string | number | boolean | null>).value, o);
  const allowed = [...byValue.keys()].map((x) => JSON.stringify(x)).join(", ");
  return new Schema<Output<T[number]>, Input<T[number]>>(
    (v, p, i) => {
      if (!isObject(v)) return expected(i, p, "object", v);
      const option = Object.hasOwn(v, key) ? byValue.get(v[key]) : undefined;
      if (!option) return fail(i, [...p, key], `must be one of: ${allowed}`);
      return option.check(v, p, i) as Output<T[number]> | Fail;
    },
    false,
    { oneOf: options.map((o) => o.json) },
  );
}

export const b = {
  string,
  number,
  boolean,
  unknown,
  literal,
  enum: enumOf,
  object,
  array,
  tuple,
  record,
  union,
  discriminatedUnion,
  coerce: { number: () => new NumberSchema([], true) },
};

export declare namespace b {
  type infer<S> = Output<S>;
  type output<S> = Output<S>;
  type input<S> = Input<S>;
  type Schema<T = unknown> = import("./schema.ts").Schema<T, unknown, boolean, boolean>;
  type ValidationError = import("./schema.ts").ValidationError;
}
