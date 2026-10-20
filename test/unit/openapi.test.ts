import { describe, expect, test } from "bun:test";
import { OPERATIONS, openApi } from "../../src/http/openapi.ts";
import { checkJson } from "../support/json-schema.ts";

const ROOT = `${import.meta.dir}/../..`;

function routesIn(source: string): string[] {
  const out: string[] = [];
  const re = /^ {6}"(\/[^"]*)": \{?\s*$|^ {4}"(\/[^"]*)": \(?/gm;
  for (const m of source.matchAll(re)) {
    const path = (m[1] ?? m[2]) as string;
    const block = source.slice((m.index ?? 0) + m[0].length);
    const end = block.search(/^ {6}"\/|^ {4}"\/|^ {4}\},?$|^ {2}\};?$/m);
    const body = end === -1 ? block : block.slice(0, end);
    const methods = [...body.matchAll(/^ {8}(GET|POST|PATCH|DELETE|PUT):/gm)].map((x) => x[1]);
    if (methods.length === 0) out.push(`GET ${path}`);
    for (const method of methods) out.push(`${method} ${path}`);
  }
  return out;
}

describe("OpenAPI description", () => {
  test("openapi.json is up to date (bun run openapi)", async () => {
    const file = await Bun.file(`${ROOT}/openapi.json`).text();
    expect(file).toBe(`${JSON.stringify(openApi(), null, 2)}\n`);
  });

  test("every route of the API is described, and nothing else", async () => {
    const app = routesIn(await Bun.file(`${ROOT}/src/http/app.ts`).text());
    const track = ["GET /o/:token", "GET /c/:token/:url"];
    const served = [...app, ...track].sort();
    const described = OPERATIONS.map((o) => `${o.method} ${o.path}`).sort();
    expect(described).toEqual(served);
  });

  test("operation ids are unique", () => {
    const ids = OPERATIONS.map((o) => o.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("request examples pass their schemas", () => {
    const doc = openApi();
    const send = { $ref: "#/components/schemas/SendEmail" };
    expect(
      checkJson(
        send,
        { from: "a@example.com", to: ["b@example.org"], subject: "s", text: "t" },
        doc,
      ),
    ).toEqual([]);
    expect(checkJson(send, { from: "a@example.com", to: 1 }, doc)).not.toEqual([]);
  });
});
