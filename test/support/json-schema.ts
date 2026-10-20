type Json = Record<string, unknown>;

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

function typeMatches(want: string, have: string): boolean {
  return want === have || (want === "number" && have === "integer");
}

export function checkJson(schema: Json, value: unknown, root: Json, path = "$"): string[] {
  if (typeof schema["$ref"] === "string") {
    const name = (schema["$ref"] as string).split("/").at(-1) as string;
    const target = (root["components"] as { schemas: Record<string, Json> }).schemas[name];
    return target ? checkJson(target, value, root, path) : [`${path}: unknown $ref ${name}`];
  }
  for (const key of ["anyOf", "oneOf"] as const) {
    const options = schema[key] as Json[] | undefined;
    if (options) {
      const tried = options.map((o) => checkJson(o, value, root, path));
      if (tried.some((t) => t.length === 0)) return [];
      return [`${path}: matches no ${key} option (${tried.map((t) => t[0]).join("; ")})`];
    }
  }
  const have = typeOf(value);
  if ("const" in schema && schema["const"] !== value) {
    return [`${path}: expected ${JSON.stringify(schema["const"])}`];
  }
  if (Array.isArray(schema["enum"]) && !(schema["enum"] as unknown[]).includes(value)) {
    return [`${path}: ${JSON.stringify(value)} is not one of ${JSON.stringify(schema["enum"])}`];
  }
  const type = schema["type"];
  if (type !== undefined) {
    const types = Array.isArray(type) ? (type as string[]) : [type as string];
    if (!types.some((t) => typeMatches(t, have)))
      return [`${path}: expected ${types}, got ${have}`];
  }
  const out: string[] = [];
  if (have === "object") {
    const v = value as Json;
    const props = schema["properties"] as Record<string, Json> | undefined;
    if (props) {
      for (const k of (schema["required"] as string[] | undefined) ?? []) {
        if (!(k in v)) out.push(`${path}.${k}: missing`);
      }
      for (const [k, item] of Object.entries(v)) {
        const p = props[k];
        if (!p) out.push(`${path}.${k}: not in the schema`);
        else out.push(...checkJson(p, item, root, `${path}.${k}`));
      }
    }
    const extra = schema["additionalProperties"] as Json | undefined;
    if (extra && !props) {
      for (const [k, item] of Object.entries(v))
        out.push(...checkJson(extra, item, root, `${path}.${k}`));
    }
  }
  if (have === "array" && schema["items"]) {
    (value as unknown[]).forEach((item, i) => {
      out.push(...checkJson(schema["items"] as Json, item, root, `${path}[${i}]`));
    });
  }
  return out;
}
