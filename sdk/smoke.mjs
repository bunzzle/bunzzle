const args = globalThis.Deno ? globalThis.Deno.args : globalThis.process.argv.slice(2);
const { Bunzzle, BunzzleError } = await import(new URL(`file://${args[0]}`).href);

const seen = [];
const fetch = async (url, init) => {
  const u = new URL(url);
  seen.push({ method: init.method, path: u.pathname, search: u.search, headers: init.headers });
  if (u.pathname === "/emails/missing") {
    return new Response(
      JSON.stringify({ statusCode: 404, name: "not_found", message: "email not found" }),
      { status: 404, headers: { "content-type": "application/json" } },
    );
  }
  return new Response(JSON.stringify({ object: "list", data: [], id: "x" }), {
    headers: { "content-type": "application/json" },
  });
};

const check = (ok, what) => {
  if (!ok) throw new Error(`SDK smoke test failed: ${what}`);
};

const client = new Bunzzle({ apiKey: "bz_smoke", baseUrl: "http://127.0.0.1:3000", fetch });
await client.sendEmail(
  { from: "a@acme.test", to: "b@example.test", subject: "s", text: "t" },
  { idempotencyKey: "k1" },
);
await client.listEmails({ to: "b@example.test", limit: 5 });
await client.createProjectKey("shop", { name: "app" });
await client.deleteSuppression("x+y@example.test", { scope: "bulk" });
let refused = null;
try {
  await client.getEmail("missing");
} catch (err) {
  refused = err;
}

const header = (h, name) =>
  h instanceof Headers
    ? h.get(name)
    : Object.entries(h ?? {}).find(([k]) => k.toLowerCase() === name)?.[1];

check(seen[0].method === "POST" && seen[0].path === "/emails", "sendEmail request");
check(header(seen[0].headers, "authorization") === "Bearer bz_smoke", "authorization header");
check(header(seen[0].headers, "idempotency-key") === "k1", "idempotency key header");
check(seen[1].search.includes("limit=5"), "query values");
check(seen[2].path === "/projects/shop/keys", "path values");
check(seen[3].path === "/suppressions/x%2By@example.test", "path encoding");
check(refused instanceof BunzzleError && refused.statusCode === 404, "BunzzleError");
console.log(`SDK works: ${seen.length} requests`);
