import { describe, expect, test } from "bun:test";
import { format, generate } from "../../sdk/generate.ts";

const ROOT = `${import.meta.dir}/../..`;

describe("TypeScript SDK", () => {
  test("the generated files are up to date (bun run openapi)", async () => {
    const out = generate(await Bun.file(`${ROOT}/openapi.json`).json());
    expect(await Bun.file(`${ROOT}/sdk/typescript/index.js`).text()).toBe(
      await format("index.js", out.js),
    );
    expect(await Bun.file(`${ROOT}/sdk/typescript/index.d.ts`).text()).toBe(
      await format("index.d.ts", out.dts),
    );
  });

  test("the type declarations compile on their own", async () => {
    const r =
      await Bun.$`bunx tsc --ignoreConfig --noEmit --strict --exactOptionalPropertyTypes --skipLibCheck false --lib ESNext,DOM ${ROOT}/sdk/typescript/index.d.ts`
        .nothrow()
        .quiet();
    expect(r.stdout.toString() + r.stderr.toString()).toBe("");
    expect(r.exitCode).toBe(0);
  });

  test("requests: path values encoded, query and headers only when set, errors thrown", async () => {
    const { Bunzzle, BunzzleError } = await import("../../sdk/typescript/index.js");
    const seen: { method: string; url: string; headers: Headers; body: string | null }[] = [];
    const fake = async (input: URL | Request | string, init?: RequestInit) => {
      const url = String(input);
      seen.push({
        method: init?.method ?? "GET",
        url,
        headers: new Headers(init?.headers),
        body: (init?.body as string | undefined) ?? null,
      });
      if (url.endsWith("/emails/missing")) {
        return Response.json(
          { statusCode: 404, name: "not_found", message: "Email not found" },
          { status: 404 },
        );
      }
      return url.endsWith("/metrics") ? new Response("# EOF\n") : Response.json({ ok: true });
    };
    const client = new Bunzzle({
      apiKey: "bz_test",
      baseUrl: "http://bz.test/",
      fetch: fake as typeof fetch,
    });
    await client.sendEmail({ from: "a@b.c", to: "d@e.f", subject: "s", text: "t" });
    await client.sendEmail(
      { from: "a@b.c", to: "d@e.f", subject: "s", text: "t" },
      { idempotencyKey: "k1" },
    );
    await client.listEmails({ to: "x@y.z", limit: 5 });
    await client.deleteSuppression("x+1@y.z");
    await client.resumeDelivery("domain:example.com");
    expect(await client.getMetrics()).toBe("# EOF\n");
    const err = await client.getEmail("missing").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BunzzleError);
    expect(err).toMatchObject({ statusCode: 404, name: "not_found", message: "Email not found" });

    expect(seen.map((r) => `${r.method} ${r.url}`)).toEqual([
      "POST http://bz.test/emails",
      "POST http://bz.test/emails",
      "GET http://bz.test/emails?to=x%40y.z&limit=5",
      "DELETE http://bz.test/suppressions/x%2B1@y.z",
      "DELETE http://bz.test/queue/suspensions/domain:example.com",
      "GET http://bz.test/metrics",
      "GET http://bz.test/emails/missing",
    ]);
    expect(seen[0]?.headers.get("authorization")).toBe("Bearer bz_test");
    expect(seen[0]?.headers.get("content-type")).toBe("application/json");
    expect(seen[0]?.headers.has("idempotency-key")).toBe(false);
    expect(seen[1]?.headers.get("idempotency-key")).toBe("k1");
    expect(JSON.parse(seen[0]?.body ?? "")).toMatchObject({ from: "a@b.c" });
    expect(seen[2]?.headers.has("content-type")).toBe(false);
  });

  test("an API key is required", async () => {
    const { Bunzzle } = await import("../../sdk/typescript/index.js");
    const saved = Bun.env["BUNZZLE_API_KEY"];
    delete Bun.env["BUNZZLE_API_KEY"];
    try {
      expect(() => new Bunzzle()).toThrow("API key");
    } finally {
      if (saved !== undefined) Bun.env["BUNZZLE_API_KEY"] = saved;
    }
  });
});
