import { describe, expect, test } from "bun:test";

const ROOT = `${import.meta.dir}/../..`;
const SELF = "test/unit/bun-only.test.ts";

const PROCESS_ALLOWED = new Set(["exit", "exitCode", "on", "send", "execPath", "kill"]);
const NODE_GLOBALS_ALLOWED = new Set(["setImmediate", "clearImmediate"]);
const NODE_GLOBALS =
  /(?<=^|[^\w$#.]|globalThis\s*\.\s*)(Buffer|global|setImmediate|clearImmediate|__dirname|__filename)(?![\w$]|\s*:)/g;

const FORBIDDEN: [RegExp, string][] = [
  [/(?<![\w.$])require\s*\(/, "calls require"],
  [/\bmodule\.exports\b|(?<![\w.$])exports\.\w+\s*=/, "uses CommonJS exports"],
  [/\bglobalThis\s*\[/, "reaches globalThis by computed name"],
];

const transpilers = {
  ts: new Bun.Transpiler({ loader: "ts" }),
  js: new Bun.Transpiler({ loader: "js" }),
};

async function files(): Promise<string[]> {
  const out: string[] = [];
  for (const dir of ["src", "test", "bench", "sdk"]) {
    for await (const f of new Bun.Glob("**/*.{ts,js,mjs}").scan({ cwd: `${ROOT}/${dir}` })) {
      const path = `${dir}/${f}`;
      if (path !== SELF && !path.endsWith(".d.ts")) out.push(path);
    }
  }
  return out.sort();
}

function withoutShebang(text: string): string {
  return text.startsWith("#!") ? text.slice(text.indexOf("\n")) : text;
}

const REGEX_BEFORE = new Set([
  "",
  "(",
  ",",
  "=",
  ":",
  "[",
  "!",
  "&",
  "|",
  "?",
  "{",
  "}",
  ";",
  "+",
  "-",
  "*",
  "%",
  "<",
  ">",
  "~",
  "^",
]);

function codeOnly(text: string): string {
  let out = "";
  let i = 0;
  const templates: number[] = [];
  let last = "";
  const skip = (end: number) => {
    out += text.slice(i, end).replace(/[^\n]/g, " ");
    i = end;
  };
  while (i < text.length) {
    const c = text[i] as string;
    const next = text[i + 1];
    if (c === "/" && next === "/") {
      const end = text.indexOf("\n", i);
      skip(end < 0 ? text.length : end);
    } else if (c === "/" && next === "*") {
      const end = text.indexOf("*/", i + 2);
      skip(end < 0 ? text.length : end + 2);
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < text.length && text[j] !== c && text[j] !== "\n") j += text[j] === "\\" ? 2 : 1;
      out += c;
      i++;
      skip(j);
      out += c;
      i = j + 1;
      last = c;
    } else if (c === "`" || (c === "}" && templates.at(-1) === 0)) {
      if (c === "}") templates.pop();
      out += c;
      let j = i + 1;
      while (j < text.length && text[j] !== "`" && !(text[j] === "$" && text[j + 1] === "{")) {
        j += text[j] === "\\" ? 2 : 1;
      }
      i++;
      skip(j);
      if (text[j] === "$") {
        out += "${";
        i = j + 2;
        templates.push(0);
        last = "{";
      } else {
        out += "`";
        i = j + 1;
        last = "`";
      }
    } else if (c === "/" && REGEX_BEFORE.has(last)) {
      let j = i + 1;
      let inClass = false;
      while (j < text.length && text[j] !== "\n" && (inClass || text[j] !== "/")) {
        if (text[j] === "[") inClass = true;
        else if (text[j] === "]") inClass = false;
        j += text[j] === "\\" ? 2 : 1;
      }
      out += "/";
      i++;
      skip(j);
      out += "/";
      i = j + 1;
      last = "/";
    } else {
      const depth = templates.length - 1;
      if (depth >= 0 && (c === "{" || c === "}")) {
        templates[depth] = (templates[depth] as number) + (c === "{" ? 1 : -1);
      }
      out += c;
      i++;
      if (!/\s/.test(c)) last = /[\w$]/.test(c) ? "w" : c;
    }
  }
  return out;
}

function lines(text: string): { n: number; line: string }[] {
  return text.split("\n").map((line, i) => ({ n: i + 1, line }));
}

function problemsIn(source: string): string[] {
  const problems: string[] = [];
  for (const { n, line } of lines(codeOnly(withoutShebang(source)))) {
    for (const [re, what] of FORBIDDEN) {
      if (re.test(line)) problems.push(`${n} ${what}`);
    }
    for (const m of line.matchAll(/(?<![\w.$])process\b(?:\s*\.\s*(\w+))?/g)) {
      if (m[1] === undefined || !PROCESS_ALLOWED.has(m[1])) {
        problems.push(`${n} uses process${m[1] ? `.${m[1]}` : ""}; use the Bun API for it`);
      }
    }
    for (const m of line.matchAll(NODE_GLOBALS)) {
      if (!NODE_GLOBALS_ALLOWED.has(m[1] as string)) problems.push(`${n} uses ${m[1]}`);
    }
  }
  return problems;
}

function allowedImport(spec: string): boolean {
  return spec.startsWith(".") || spec === "bun" || spec.startsWith("bun:");
}

describe("Bun only", () => {
  test("imports are relative or bun", async () => {
    const problems: string[] = [];
    for (const path of await files()) {
      const text = withoutShebang(await Bun.file(`${ROOT}/${path}`).text());
      const t = path.endsWith(".ts") ? transpilers.ts : transpilers.js;
      for (const { path: spec } of t.scanImports(text)) {
        if (!allowedImport(spec)) problems.push(`${path} imports ${spec}`);
      }
    }
    expect(problems).toEqual([]);
  });

  test("no Node APIs or CommonJS in our code", async () => {
    const problems: string[] = [];
    for (const path of await files()) {
      const text = await Bun.file(`${ROOT}/${path}`).text();
      for (const p of problemsIn(text)) problems.push(`${path}:${p}`);
    }
    expect(problems).toEqual([]);
  });

  test("the check sees through destructuring, globalThis and strings", () => {
    expect(problemsIn("const { env } = process;")).toHaveLength(1);
    expect(problemsIn("globalThis.Buffer.from(x);")).toHaveLength(1);
    expect(problemsIn("const g = global;")).toHaveLength(1);
    expect(problemsIn("this.#global = stats.global;")).toEqual([]);
    expect(problemsIn("process.env.HOME;")).toHaveLength(1);
    expect(problemsIn('throw new Error("process restarted");')).toEqual([]);
    const template = (inner: string) => `const s = \`the $\{${inner}} process\`;`;
    expect(problemsIn(template("name"))).toEqual([]);
    expect(problemsIn(template("process.env.X"))).toHaveLength(1);
    expect(problemsIn("const re = /global|process/g;")).toEqual([]);
    expect(problemsIn("setImmediate(() => flush());")).toEqual([]);
  });

  test("no runtime dependencies", async () => {
    for (const pkg of ["package.json", "sdk/typescript/package.json"]) {
      const meta = (await Bun.file(`${ROOT}/${pkg}`).json()) as Record<string, unknown>;
      for (const field of ["dependencies", "peerDependencies", "optionalDependencies"]) {
        expect(meta[field], `${pkg} ${field}`).toBeUndefined();
      }
    }
  });
});
