export class TemplateError extends Error {}

export class MissingVariables extends Error {
  constructor(readonly names: string[]) {
    super(`missing variables: ${names.join(", ")}`);
  }
}

type Node =
  | { kind: "text"; value: string }
  | { kind: "var"; path: string; raw: boolean }
  | { kind: "if"; path: string; yes: Node[]; no: Node[] }
  | { kind: "each"; path: string; body: Node[] };

export type Template = Node[];

export const MAX_DEPTH = 10;
export const MAX_OUTPUT = 40 * 1024 * 1024;

const PATH = /^(this|[A-Za-z_][A-Za-z0-9_-]*)(\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const TAG = /\{\{\{\s*([^{}]*?)\s*\}\}\}|\{\{\s*([^{}]*?)\s*\}\}/g;

function lineOf(source: string, at: number): number {
  let line = 1;
  for (let i = 0; i < at; i++) if (source.charCodeAt(i) === 10) line++;
  return line;
}

export function parse(source: string): Template {
  const root: Node[] = [];
  const stack: { node: Extract<Node, { kind: "if" | "each" }>; into: Node[]; line: number }[] = [];
  let out = root;
  let last = 0;
  function fail(at: number, message: string): never {
    throw new TemplateError(`line ${lineOf(source, at)}: ${message}`);
  }
  const path = (at: number, p: string) => {
    if (!PATH.test(p)) fail(at, `\`${p}\` is not a variable name`);
    return p;
  };
  for (const m of source.matchAll(TAG)) {
    const at = m.index;
    if (at > last) out.push({ kind: "text", value: source.slice(last, at) });
    last = at + m[0].length;
    if (m[1] !== undefined) {
      out.push({ kind: "var", path: path(at, m[1]), raw: true });
      continue;
    }
    const tag = m[2] as string;
    const open = /^#(if|each)\s+(\S+)$/.exec(tag);
    if (open) {
      if (stack.length >= MAX_DEPTH) fail(at, `blocks nest deeper than ${MAX_DEPTH}`);
      const p = path(at, open[2] as string);
      const node: Extract<Node, { kind: "if" | "each" }> =
        open[1] === "if"
          ? { kind: "if", path: p, yes: [], no: [] }
          : { kind: "each", path: p, body: [] };
      out.push(node);
      stack.push({ node, into: out, line: lineOf(source, at) });
      out = node.kind === "if" ? node.yes : node.body;
      continue;
    }
    if (tag === "else") {
      const top = stack.at(-1);
      if (top?.node.kind !== "if" || out !== top.node.yes) {
        fail(at, "`{{else}}` outside `{{#if}}`");
      }
      out = top.node.no;
      continue;
    }
    const close = /^\/(if|each)$/.exec(tag);
    if (close) {
      const top = stack.pop();
      if (!top) fail(at, `\`{{/${close[1]}}}\` without an opening block`);
      if (top.node.kind !== close[1]) {
        fail(at, `\`{{/${close[1]}}}\` closes \`{{#${top.node.kind}}}\``);
      }
      out = top.into;
      continue;
    }
    if (tag.startsWith("#") || tag.startsWith("/")) fail(at, `unknown block \`{{${tag}}}\``);
    out.push({ kind: "var", path: path(at, tag), raw: false });
  }
  const open = stack.at(-1);
  if (open) {
    throw new TemplateError(`line ${open.line}: \`{{#${open.node.kind}}}\` is never closed`);
  }
  if (last < source.length) out.push({ kind: "text", value: source.slice(last) });
  return root;
}

const ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => ESCAPES[c] as string);

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function lookup(scopes: unknown[], path: string): { found: boolean; value: unknown } {
  const [head, ...rest] = path.split(".") as [string, ...string[]];
  let value: unknown;
  let found = false;
  if (head === "this") {
    value = scopes.at(-1);
    found = true;
  } else {
    for (let i = scopes.length - 1; i >= 0; i--) {
      const s = scopes[i];
      if (isObject(s) && Object.hasOwn(s, head)) {
        value = s[head];
        found = true;
        break;
      }
    }
  }
  for (const key of rest) {
    if (!found || !isObject(value) || !Object.hasOwn(value, key)) return { found: false, value };
    value = value[key];
  }
  return { found, value };
}

const truthy = (v: unknown) =>
  Array.isArray(v)
    ? v.length > 0
    : v !== undefined && v !== null && v !== false && v !== "" && v !== 0;

export function render(
  template: Template,
  variables: Record<string, unknown>,
  mode: "html" | "text",
): string {
  const missing = new Set<string>();
  const parts: string[] = [];
  let size = 0;
  const push = (s: string) => {
    size += s.length;
    if (size > MAX_OUTPUT) throw new TemplateError(`the result is larger than ${MAX_OUTPUT} bytes`);
    parts.push(s);
  };
  const walk = (nodes: Node[], scopes: unknown[]) => {
    for (const n of nodes) {
      if (n.kind === "text") {
        push(n.value);
        continue;
      }
      const { found, value } = lookup(scopes, n.path);
      if (n.kind === "if") {
        walk(found && truthy(value) ? n.yes : n.no, scopes);
        continue;
      }
      if (!found) {
        missing.add(n.path);
        continue;
      }
      if (n.kind === "each") {
        if (value === null) continue;
        if (!Array.isArray(value)) throw new TemplateError(`\`${n.path}\` must be a list`);
        for (const item of value) walk(n.body, [...scopes, item]);
        continue;
      }
      if (value === null) continue;
      if (typeof value === "object") {
        throw new TemplateError(`\`${n.path}\` must be text, a number or true/false`);
      }
      const s = String(value);
      push(mode === "html" && !n.raw ? escapeHtml(s) : s);
    }
  };
  walk(template, [variables]);
  if (missing.size > 0) throw new MissingVariables([...missing]);
  return parts.join("");
}
