import { describe, expect, test } from "bun:test";
import { b, ValidationError } from "../../src/validate/schema.ts";

const issue = (r: { success: boolean; error?: ValidationError }) => r.error?.issues[0];

describe("b", () => {
  test("plain messages with the path of the field", () => {
    const s = b.object({
      to: b.array(b.string().min(3).max(10)).max(2),
      port: b.number().int().min(1),
      kind: b.enum(["a", "b"]),
      tag: b.literal("x"),
    });
    expect(issue(s.safeParse({ to: ["ab"], port: 1, kind: "a", tag: "x" }))).toEqual({
      path: ["to", 0],
      message: "must be at least 3 characters",
    });
    expect(issue(s.safeParse({ to: [], port: 1.5, kind: "a", tag: "x" }))?.message).toBe(
      "must be a whole number",
    );
    expect(issue(s.safeParse({ to: [], port: 1, kind: "c", tag: "x" }))?.message).toBe(
      "must be one of: a, b",
    );
    expect(issue(s.safeParse({ to: [], port: 1, kind: "a" }))).toEqual({
      path: ["tag"],
      message: "is required",
    });
    expect(issue(s.safeParse({ to: "x", port: 1, kind: "a", tag: "x" }))?.message).toBe(
      "expected array, got string",
    );
    expect(() => s.parse(null)).toThrow(ValidationError);
  });

  test("only own keys are read, unknown keys are dropped, __proto__ cannot change the prototype", () => {
    const s = b.object({ constructor: b.string().optional(), a: b.number() });
    expect(s.parse({ a: 1 }) as object).toEqual({ a: 1 });
    const r = b.record(b.string(), b.number()).parse(JSON.parse('{"__proto__": 5, "x": 1}'));
    expect(Object.getPrototypeOf(r)).toBe(Object.prototype);
    expect(Object.keys(r)).toEqual(["__proto__", "x"]);
    expect(b.object({ a: b.number() }).parse({ a: 1, extra: 2 })).toEqual({ a: 1 });
  });

  test("optional, nullable, default, transform, refine, coerce", () => {
    const s = b.object({
      a: b.string().optional(),
      n: b.enum(["x"]).nullable().default(null),
      list: b.array(b.string()).default([]),
      flag: b
        .enum(["true", "false"])
        .optional()
        .transform((v) => v === "true"),
      port: b.coerce.number().int().default(25),
    });
    const one = s.parse({});
    const two = s.parse({});
    expect(one).toEqual({ n: null, list: [], flag: false, port: 25 });
    one.list.push("changed");
    expect(two.list).toEqual([]);
    expect(s.parse({ port: "587", flag: "true" }).port).toBe(587);
    expect(s.safeParse({ port: "x" }).success).toBe(false);
    const even = b.number().refine((n) => n % 2 === 0, { message: "must be even" });
    expect(issue(even.safeParse(3))?.message).toBe("must be even");
  });

  test("unions and discriminated unions", () => {
    const u = b.union([b.string(), b.array(b.string()).min(1)]);
    expect(u.parse("a")).toBe("a");
    expect(u.parse(["a"])).toEqual(["a"]);
    expect(issue(u.safeParse([]))?.message).toBe("does not match any allowed form");
    const d = b.discriminatedUnion("kind", [
      b.object({ kind: b.literal("mx"), host: b.string() }),
      b.object({ kind: b.literal("none") }),
    ]);
    expect(d.parse({ kind: "mx", host: "h", x: 1 })).toEqual({ kind: "mx", host: "h" });
    expect(issue(d.safeParse({ kind: "other" }))).toEqual({
      path: ["kind"],
      message: 'must be one of: "mx", "none"',
    });
  });

  test("omit, url and email", () => {
    const s = b.object({ a: b.string(), token: b.string() }).omit({ token: true });
    expect(s.parse({ a: "x", token: "y" })).toEqual({ a: "x" });
    expect(b.string().url().safeParse("https://x.test/p").success).toBe(true);
    expect(b.string().url().safeParse("not a url").success).toBe(false);
    expect(b.string().email().safeParse("a.b+c@mail.example.com").success).toBe(true);
    expect(b.string().email().safeParse("a@b").success).toBe(false);
    expect(b.string().email().safeParse("a b@c.com").success).toBe(false);
  });

  test("types follow the schema", () => {
    const s = b.object({
      a: b.string(),
      o: b.number().optional(),
      d: b.boolean().default(false),
      u: b.union([b.literal(4), b.literal(6)]),
    });
    const out: b.infer<typeof s> = { a: "x", d: true, u: 4 };
    const input: b.input<typeof s> = { a: "x", u: 6 };
    const schema: b.Schema<{ a: string }> = b.object({ a: b.string() });
    expect([out.a, input.a, schema.parse({ a: "y" }).a]).toEqual(["x", "x", "y"]);
  });

  test("tuple: fixed length, each item checked by its own schema", () => {
    const t = b.tuple([b.number().int(), b.enum(["C", "S"]), b.string().max(3)]);
    expect(t.parse([1, "C", "abc"])).toEqual([1, "C", "abc"]);
    expect(t.safeParse([1, "C"]).success).toBe(false);
    expect(t.safeParse([1, "C", "abc", 4]).success).toBe(false);
    const bad = t.safeParse([1.5, "X", "abcd"]);
    expect(bad.success).toBe(false);
    if (!bad.success) expect(bad.error.issues.map((x) => x.path)).toEqual([[0], [1], [2]]);
    expect(t.safeParse("nope").success).toBe(false);
  });
});
