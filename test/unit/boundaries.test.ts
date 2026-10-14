// Architecture rules enforced as tests (architecture.md §13, §14):
//  1. src/core never imports from outside src/core (keeps the framework extractable).
//  2. Nothing in src imports node: modules (Bun built-ins only).
import { describe, expect, test } from "bun:test";

const SRC = `${import.meta.dir}/../../src`;
const IMPORT_RE =
  /(?:import|export)\s[^"'`]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

async function sourceFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  for await (const f of new Bun.Glob("**/*.ts").scan({ cwd: dir })) files.push(`${dir}/${f}`);
  return files;
}

async function importsOf(file: string): Promise<string[]> {
  const text = await Bun.file(file).text();
  return [...text.matchAll(IMPORT_RE)].map((m) => (m[1] ?? m[2]) as string);
}

function resolve(from: string, spec: string): string {
  const parts = from.split("/").slice(0, -1);
  for (const seg of spec.split("/")) {
    if (seg === "..") parts.pop();
    else if (seg !== ".") parts.push(seg);
  }
  return parts.join("/");
}

describe("architecture boundaries", () => {
  test("src/core imports only from src/core and bun: modules", async () => {
    const core = `${SRC}/core`;
    const violations: string[] = [];
    for (const file of await sourceFiles(core)) {
      for (const spec of await importsOf(file)) {
        if (spec.startsWith("bun:")) continue;
        if (!spec.startsWith(".") || !resolve(file, spec).startsWith(core)) {
          violations.push(`${file.slice(SRC.length)} -> ${spec}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  test("no node: modules anywhere in src", async () => {
    const violations: string[] = [];
    for (const file of await sourceFiles(SRC)) {
      for (const spec of await importsOf(file)) {
        if (spec.startsWith("node:")) violations.push(`${file.slice(SRC.length)} -> ${spec}`);
      }
    }
    expect(violations).toEqual([]);
  });
});
