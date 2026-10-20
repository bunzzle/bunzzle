type Json = Record<string, unknown>;

interface Parameter {
  name: string;
  in: "path" | "query" | "header";
  schema: Json;
}

interface Operation {
  operationId: string;
  tags: string[];
  parameters?: Parameter[];
  requestBody?: { content: Record<string, { schema: Json }> };
  responses: Record<string, { content?: Record<string, { schema: Json }> }>;
}

const IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

const camel = (name: string) =>
  name
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w, i) => (i === 0 ? w.toLowerCase() : w[0]?.toUpperCase() + w.slice(1).toLowerCase()))
    .join("");

function typeOf(s: Json, indent = ""): string {
  if (typeof s["$ref"] === "string") return (s["$ref"] as string).split("/").at(-1) as string;
  for (const key of ["anyOf", "oneOf"]) {
    if (Array.isArray(s[key])) {
      return [...new Set((s[key] as Json[]).map((o) => typeOf(o, indent)))].join(" | ");
    }
  }
  if ("const" in s) return JSON.stringify(s["const"]);
  if (Array.isArray(s["enum"]))
    return (s["enum"] as unknown[]).map((v) => JSON.stringify(v)).join(" | ");
  if (Array.isArray(s["type"])) {
    return (s["type"] as string[]).map((t) => typeOf({ ...s, type: t }, indent)).join(" | ");
  }
  switch (s["type"]) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "null":
      return "null";
    case "array": {
      if (Array.isArray(s["prefixItems"])) {
        return `[${(s["prefixItems"] as Json[]).map((x) => typeOf(x, indent)).join(", ")}]`;
      }
      const item = typeOf((s["items"] as Json | undefined) ?? {}, indent);
      return /[ |]/.test(item) ? `(${item})[]` : `${item}[]`;
    }
    case "object": {
      const props = s["properties"] as Record<string, Json> | undefined;
      if (!props) {
        return `Record<string, ${typeOf((s["additionalProperties"] as Json | undefined) ?? {}, indent)}>`;
      }
      const required = new Set((s["required"] as string[] | undefined) ?? []);
      const inner = `${indent}  `;
      const lines = Object.entries(props).map(([k, v]) => {
        const key = IDENT.test(k) ? k : JSON.stringify(k);
        return `${inner}${key}${required.has(k) ? "" : "?"}: ${typeOf(v, inner)};`;
      });
      return lines.length ? `{\n${lines.join("\n")}\n${indent}}` : "Record<string, never>";
    }
    default:
      return "unknown";
  }
}

const jsonSchema = (content?: Record<string, { schema: Json }>) =>
  content?.["application/json"]?.schema;

export async function format(path: string, source: string): Promise<string> {
  return Bun.$`biome format --stdin-file-path=${path} < ${new Response(source)}`.text();
}

export function generate(doc: Json): { js: string; dts: string } {
  const schemas = (doc["components"] as { schemas: Record<string, Json> }).schemas;
  const version = (doc["info"] as { version: string }).version;
  const dts: string[] = [];
  const js: string[] = [];

  for (const [name, schema] of Object.entries(schemas)) {
    dts.push(`export type ${name} = ${typeOf(schema)};`, "");
  }
  dts.push(
    "export interface BunzzleOptions {",
    "  apiKey?: string;",
    "  baseUrl?: string;",
    "  fetch?: typeof fetch;",
    "}",
    "",
    "export declare class BunzzleError extends Error {",
    "  readonly statusCode: number;",
    "  readonly name: string;",
    "  constructor(statusCode: number, name: string, message: string);",
    "}",
    "",
  );
  js.push(
    `export const VERSION = ${JSON.stringify(version)};`,
    "",
    "export class BunzzleError extends Error {",
    "  constructor(statusCode, name, message) {",
    "    super(message);",
    "    this.statusCode = statusCode;",
    "    this.name = name;",
    "  }",
    "}",
    "",
    "const segment = (v) =>",
    '  encodeURIComponent(String(v)).replace(/%3A/gi, ":").replace(/%40/g, "@");',
    "",
    "export class Bunzzle {",
    "  #key;",
    "  #base;",
    "  #fetch;",
    "",
    "  constructor(options = {}) {",
    "    const key = options.apiKey ?? globalThis.process?.env?.BUNZZLE_API_KEY;",
    '    if (!key) throw new Error("Bunzzle needs an API key: pass apiKey or set BUNZZLE_API_KEY");',
    "    this.#key = key;",
    "    this.#base = (",
    "      options.baseUrl ??",
    "      globalThis.process?.env?.BUNZZLE_URL ??",
    '      "http://127.0.0.1:3000"',
    '    ).replace(/\\/+$/, "");',
    "    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);",
    "  }",
    "",
    "  async #request(method, path, { query, body, headers, text } = {}) {",
    "    const url = new URL(this.#base + path);",
    "    for (const [k, v] of Object.entries(query ?? {})) {",
    "      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));",
    "    }",
    "    const res = await this.#fetch(url, {",
    "      method,",
    "      headers: {",
    `        authorization: \`Bearer \${this.#key}\`,`,
    '        ...(body === undefined ? {} : { "content-type": "application/json" }),',
    "        ...Object.fromEntries(Object.entries(headers ?? {}).filter(([, v]) => v !== undefined)),",
    "      },",
    "      ...(body === undefined ? {} : { body: JSON.stringify(body) }),",
    "    });",
    "    if (!res.ok) {",
    "      const e = await res.json().catch(() => ({}));",
    '      throw new BunzzleError(res.status, e.name ?? "http_error", e.message ?? res.statusText);',
    "    }",
    "    return text ? res.text() : res.json();",
    "  }",
  );
  dts.push(
    "export declare const VERSION: string;",
    "",
    "export declare class Bunzzle {",
    "  constructor(options?: BunzzleOptions);",
  );

  const paths = doc["paths"] as Record<string, Record<string, Operation>>;
  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (op.tags.includes("Public links")) continue;
      const params = op.parameters ?? [];
      const pathParams = params.filter((p) => p.in === "path");
      const query = params.filter((p) => p.in === "query");
      const headers = params.filter((p) => p.in === "header");
      const body = jsonSchema(op.requestBody?.content);
      const ok = op.responses["200"];
      const result = jsonSchema(ok?.content);
      const isText = !result && ok?.content !== undefined;
      const args: string[] = pathParams.map((p) => camel(p.name));
      const types: string[] = pathParams.map((p) => `${camel(p.name)}: string`);
      if (body) {
        args.push("body");
        types.push(`body: ${typeOf(body)}`);
      }
      const options = [
        ...query.map((p) => ({ key: p.name, prop: p.name, type: typeOf(p.schema, "    ") })),
        ...headers.map((p) => ({ key: p.name.toLowerCase(), prop: camel(p.name), type: "string" })),
      ];
      if (options.length) {
        args.push("options = {}");
        const fields = options.map(
          (o) => `    ${IDENT.test(o.prop) ? o.prop : JSON.stringify(o.prop)}?: ${o.type};`,
        );
        types.push(`options?: {\n${fields.join("\n")}\n  }`);
      }
      const url = path.replace(/\{(\w+)\}/g, (_, n: string) => `\${segment(${camel(n)})}`);
      const init = [
        ...(query.length
          ? [`query: { ${query.map((p) => `${p.name}: options.${p.name}`).join(", ")} }`]
          : []),
        ...(body ? ["body"] : []),
        ...(headers.length
          ? [
              `headers: { ${headers
                .map((p) => `${JSON.stringify(p.name.toLowerCase())}: options.${camel(p.name)}`)
                .join(", ")} }`,
            ]
          : []),
        ...(isText ? ["text: true"] : []),
      ];
      js.push(
        "",
        `  ${op.operationId}(${args.join(", ")}) {`,
        `    return this.#request(${JSON.stringify(method.toUpperCase())}, \`${url}\`${init.length ? `, { ${init.join(", ")} }` : ""});`,
        "  }",
      );
      const returns = result ? typeOf(result, "  ") : isText ? "string" : "unknown";
      dts.push(`  ${op.operationId}(${types.join(", ")}): Promise<${returns}>;`);
    }
  }
  js.push("}", "");
  dts.push("}", "");
  return { js: js.join("\n"), dts: dts.join("\n") };
}

if (import.meta.main) {
  const root = `${import.meta.dir}`;
  const doc = (await Bun.file(`${root}/../openapi.json`).json()) as Json;
  const out = generate(doc);
  await Bun.write(`${root}/typescript/index.js`, await format("index.js", out.js));
  await Bun.write(`${root}/typescript/index.d.ts`, await format("index.d.ts", out.dts));
}
