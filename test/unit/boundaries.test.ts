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

const VALUE_IMPORT_RE =
  /(?:^|\n)\s*(?:import|export)\s+(?!type\s)[^"'`;]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

async function valueImports(file: string): Promise<string[]> {
  const text = await Bun.file(file).text();
  return [...text.matchAll(VALUE_IMPORT_RE)].map((m) => (m[1] ?? m[2]) as string);
}

async function reachable(entry: string): Promise<Set<string>> {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const spec of await valueImports(file)) {
      if (spec.startsWith(".") && spec.endsWith(".ts")) queue.push(resolve(file, spec));
    }
  }
  return new Set([...seen].map((f) => f.slice(SRC.length + 1)));
}

const ROLE_LIMITS: Record<string, string[]> = {
  delivery: [
    "core/store/",
    "signer/",
    "dkim/keys.ts",
    "crypto/",
    "roles/core.ts",
    "net/cloudflare.ts",
  ],
  api: ["core/store/", "signer/", "dkim/", "crypto/", "smtp/", "dns/", "delivery/"],
  core: [
    "signer/",
    "dkim/keys.ts",
    "dkim/sign.ts",
    "crypto/master.ts",
    "crypto/load.ts",
    "smtp/connection.ts",
    "smtp/session.ts",
    "dns/resolver.ts",
  ],
  signer: ["core/store/", "smtp/", "dns/", "delivery/"],
  inbound: [
    "core/store/",
    "signer/",
    "dkim/keys.ts",
    "dkim/sign.ts",
    "dkim/verify.ts",
    "crypto/",
    "smtp/",
    "delivery/",
  ],
  dns: [
    "core/store/",
    "signer/",
    "dkim/",
    "crypto/",
    "smtp/",
    "smtpd/",
    "delivery/",
    "mime/",
    "inbound/",
  ],
  link: [
    "core/store/",
    "signer/",
    "dkim/",
    "crypto/",
    "smtp/",
    "smtpd/",
    "delivery/",
    "mime/",
    "inbound/",
    "nodes/",
    "net/",
    "acme/",
    "dns/resolver.ts",
  ],
  ns: [
    "core/",
    "signer/",
    "dkim/",
    "crypto/",
    "smtp/",
    "smtpd/",
    "delivery/",
    "mime/",
    "inbound/",
    "net/",
    "acme/",
    "dns/resolver.ts",
    "dns/cache.ts",
  ],
};

describe("role boundaries (what each process can even load)", () => {
  for (const [role, forbidden] of Object.entries(ROLE_LIMITS)) {
    test(`${role} cannot load ${forbidden.join(", ")}`, async () => {
      const files = await reachable(`${SRC}/roles/${role}.ts`);
      const bad = [...files].filter((f) => forbidden.some((x) => f.startsWith(x)));
      expect(bad).toEqual([]);
    });
  }

  test("only core and the CLI know the admin socket", async () => {
    for (const role of ["signer", "dns", "link", "delivery", "api", "inbound", "ns"]) {
      const files = await reachable(`${SRC}/roles/${role}.ts`);
      expect([...files].filter((f) => f === "roles/admin-socket.ts")).toEqual([]);
    }
  });

  test("only the signer and the CLI can load the master key", async () => {
    for (const role of ["delivery", "api", "core", "inbound", "link", "ns"]) {
      const files = await reachable(`${SRC}/roles/${role}.ts`);
      expect([...files].filter((f) => f === "crypto/load.ts" || f === "crypto/master.ts")).toEqual(
        [],
      );
    }
  });
});

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
