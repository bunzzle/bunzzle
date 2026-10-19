import { describe, expect, test } from "bun:test";

const ROOT = `${import.meta.dir}/../..`;
const SELF = "test/unit/bun-only.test.ts";

const PROCESS_ALLOWED = new Set(["exit", "exitCode", "on", "send", "execPath", "kill"]);

const FORBIDDEN: [RegExp, string][] = [
  [/(?:from\s*|import\(\s*|require\(\s*)["']node:/, "imports a node: module"],
  [/(?<![\w.$])require\s*\(/, "calls require"],
  [/(?<![\w.$])Buffer\b/, "uses Buffer"],
  [/\b__dirname\b|\b__filename\b/, "uses __dirname or __filename"],
  [/\bmodule\.exports\b|(?<![\w.$])exports\.\w+\s*=/, "uses CommonJS exports"],
];

async function files(): Promise<string[]> {
  const out: string[] = [];
  for (const dir of ["src", "test", "bench"]) {
    for await (const f of new Bun.Glob("**/*.ts").scan({ cwd: `${ROOT}/${dir}` })) {
      const path = `${dir}/${f}`;
      if (path !== SELF) out.push(path);
    }
  }
  return out.sort();
}

function lines(text: string): { n: number; line: string }[] {
  return text.split("\n").map((line, i) => ({ n: i + 1, line }));
}

describe("Bun only", () => {
  test("no Node APIs or CommonJS in our code", async () => {
    const problems: string[] = [];
    for (const path of await files()) {
      const text = await Bun.file(`${ROOT}/${path}`).text();
      for (const { n, line } of lines(text)) {
        for (const [re, what] of FORBIDDEN) {
          if (re.test(line)) problems.push(`${path}:${n} ${what}`);
        }
        for (const m of line.matchAll(/(?<![\w.$])process\.(\w+)/g)) {
          if (!PROCESS_ALLOWED.has(m[1] as string)) {
            problems.push(`${path}:${n} uses process.${m[1]}; use the Bun API for it`);
          }
        }
      }
    }
    expect(problems).toEqual([]);
  });

  test("no runtime dependencies that ship CommonJS or use Node APIs", async () => {
    const pkg = (await Bun.file(`${ROOT}/package.json`).json()) as {
      dependencies?: Record<string, string>;
    };
    const problems: string[] = [];
    for (const name of Object.keys(pkg.dependencies ?? {})) {
      const dir = `${ROOT}/node_modules/${name}`;
      const meta = (await Bun.file(`${dir}/package.json`).json()) as Record<string, unknown>;
      if (JSON.stringify(meta["exports"] ?? {}).includes('"require"')) {
        problems.push(`${name} has a require export`);
      }
      if (typeof meta["main"] === "string" && /\.cjs$/.test(meta["main"])) {
        problems.push(`${name} has a CommonJS main`);
      }
      for await (const f of new Bun.Glob("**/*.{js,mjs,cjs}").scan({ cwd: dir })) {
        if (f.endsWith(".cjs")) {
          problems.push(`${name} ships ${f}`);
          continue;
        }
        const text = await Bun.file(`${dir}/${f}`).text();
        for (const [re, what] of FORBIDDEN)
          if (re.test(text)) problems.push(`${name}/${f} ${what}`);
      }
    }
    expect(problems).toEqual([]);
  });
});
